package com.mirage.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONException

class MirageVpnService : VpnService(), MirageCallback {

    companion object {
        const val ACTION_CONNECT = "com.mirage.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "com.mirage.vpn.action.DISCONNECT"
        const val EXTRA_CONFIG = "com.mirage.vpn.extra.CONFIG"

        const val STATUS_DISCONNECTED = 0
        const val STATUS_CONNECTING = 1
        const val STATUS_CONNECTED = 2
        const val STATUS_ERROR = 3

        private const val TAG = "MirageVpnService"
        private const val CHANNEL_ID = "mirage_vpn"
        private const val NOTIFICATION_ID = 1

        val status = MutableStateFlow(STATUS_DISCONNECTED)
        val statusMessage = MutableStateFlow<String?>(null)

        // [bytesSent, bytesReceived, packetsSent, packetsReceived, uptimeSeconds]
        val metrics = MutableStateFlow(LongArray(5))
        val activeProtocol = MutableStateFlow("")
        val isRunning = MutableStateFlow(false)
    }

    // All lifecycle work (connect / tunnel setup / teardown) is serialized on this single
    // thread. Native callbacks only post work here, so they never run native teardown
    // calls from within a native callback thread.
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "mirage-service") }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var metricsJob: Job? = null

    // Guards the native handle. Users of the handle (sendPacket, metrics polling) hold the
    // read lock; destruction takes the write lock, so destroy can never overlap a native
    // call, and after destroy `handle` is 0 so no one calls into a freed handle.
    private val handleLock = ReentrantReadWriteLock()

    @Volatile
    private var handle = 0L

    // Set once teardown starts; late native callbacks are ignored afterwards.
    @Volatile
    private var closing = false

    // True once we saw CONNECTING/CONNECTED, so an initial DISCONNECTED is not terminal.
    @Volatile
    private var sawActive = false

    // Guards pfd / tunOut / readThread and serializes writes to the TUN.
    private val tunLock = Any()
    private var pfd: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    private var readThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Started via startForegroundService(): must enter foreground promptly.
        enterForeground(getString(R.string.notification_connecting))
        return when (intent?.action) {
            ACTION_CONNECT -> {
                val config = intent.getStringExtra(EXTRA_CONFIG)
                if (config.isNullOrBlank()) {
                    post { failAndStop("No configuration provided") }
                } else {
                    post { connect(config) }
                }
                START_STICKY
            }
            ACTION_DISCONNECT -> {
                post { disconnect() }
                START_NOT_STICKY
            }
            else -> {
                // Sticky restart with a null intent: nothing to resume (no config).
                post { teardown() }
                START_NOT_STICKY
            }
        }
    }

    override fun onRevoke() {
        post {
            teardown()
            status.value = STATUS_DISCONNECTED
            statusMessage.value = null
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        post { teardown() }
        executor.shutdown() // queued teardown still runs
        scope.cancel()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- service thread

    private fun post(block: () -> Unit) {
        try {
            executor.execute {
                try {
                    block()
                } catch (t: Throwable) {
                    Log.e(TAG, "service task failed", t)
                }
            }
        } catch (_: RejectedExecutionException) {
            // Service already destroyed.
        }
    }

    private fun connect(configToml: String) {
        if (handle != 0L) {
            Log.w(TAG, "connect ignored: already running")
            return
        }
        closing = false
        sawActive = false
        status.value = STATUS_CONNECTING
        statusMessage.value = null
        metrics.value = LongArray(5)
        activeProtocol.value = ""
        isRunning.value = true

        val h = try {
            MirageNative.nativeCreate(configToml)
        } catch (t: Throwable) { // includes UnsatisfiedLinkError if the .so is missing
            failAndStop(t.message ?: t.toString())
            return
        }
        if (h == 0L) {
            failAndStop(MirageNative.nativeLastError())
            return
        }
        handle = h
        startMetricsPolling()
        try {
            MirageNative.nativeStart(h, this)
        } catch (t: Throwable) {
            failAndStop(t.message ?: t.toString())
        }
    }

    private fun disconnect() {
        teardown()
        status.value = STATUS_DISCONNECTED
        statusMessage.value = null
        metrics.value = LongArray(5)
        activeProtocol.value = ""
    }

    private fun failAndStop(message: String) {
        status.value = STATUS_ERROR
        statusMessage.value = message
        teardown()
    }

    /**
     * Idempotent teardown; only ever runs on the service executor.
     * Order: stop native -> close TUN fd / interrupt reader -> (write lock) zero handle and
     * destroy. Holding the write lock while destroying waits out any in-flight
     * nativeSendPacket / metrics call, and zeroing the handle first stops new ones.
     */
    private fun teardown() {
        closing = true
        metricsJob?.cancel()
        metricsJob = null

        val h = handle
        if (h != 0L) {
            try {
                MirageNative.nativeStop(h)
            } catch (t: Throwable) {
                Log.w(TAG, "nativeStop failed", t)
            }
        }
        closeTun()
        if (h != 0L) {
            handleLock.write {
                handle = 0L
                try {
                    MirageNative.nativeDestroy(h)
                } catch (t: Throwable) {
                    Log.w(TAG, "nativeDestroy failed", t)
                }
            }
        }
        isRunning.value = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startMetricsPolling() {
        metricsJob?.cancel()
        metricsJob = scope.launch {
            while (isActive) {
                delay(1000)
                if (status.value != STATUS_CONNECTED) continue
                try {
                    handleLock.read {
                        val h = handle
                        if (h != 0L) {
                            metrics.value = MirageNative.nativeGetMetrics(h)
                            activeProtocol.value = MirageNative.nativeGetActiveProtocol(h)
                        }
                    }
                } catch (t: Throwable) {
                    Log.w(TAG, "metrics poll failed", t)
                }
            }
        }
    }

    // ---------------------------------------------------------------- MirageCallback

    override fun onTunnelConfig(
        clientAddress: String,
        clientAddressV6: String,
        mtu: Int,
        dnsServersJson: String,
        routesJson: String,
        excludedRoutesJson: String,
    ) {
        // Native thread: marshal to the service thread.
        post {
            if (closing || handle == 0L) return@post
            setupTun(clientAddress, clientAddressV6, mtu, dnsServersJson, routesJson, excludedRoutesJson)
        }
    }

    private fun setupTun(
        clientAddress: String,
        clientAddressV6: String,
        mtu: Int,
        dnsServersJson: String,
        routesJson: String,
        excludedRoutesJson: String,
    ) {
        val builder = Builder()
        builder.setSession("Turbo VPN")
        builder.setBlocking(true)
        if (mtu > 0) builder.setMtu(mtu)

        var hasAddress = false
        for (addr in listOf(clientAddress, clientAddressV6)) {
            if (addr.isBlank()) continue
            val (ip, prefix) = splitCidr(addr) ?: continue
            try {
                builder.addAddress(ip, prefix)
                hasAddress = true
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "bad address $addr", e)
            }
        }
        if (!hasAddress) {
            failAndStop("Server provided no valid client address")
            return
        }

        val routes = parseJsonStrings(routesJson)
        if (routes.isEmpty()) {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        } else {
            for (route in routes) {
                val (ip, prefix) = splitCidr(route) ?: continue
                try {
                    builder.addRoute(ip, prefix)
                } catch (e: IllegalArgumentException) {
                    Log.w(TAG, "bad route $route", e)
                }
            }
        }

        for (dns in parseJsonStrings(dnsServersJson)) {
            try {
                builder.addDnsServer(dns)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "bad dns server $dns", e)
            }
        }

        // Excluded routes: Builder.excludeRoute() only exists on API 33+. Older versions
        // ignore them (never fatal). Our own app is always excluded from the VPN below so
        // the Rust client's socket to the server does not loop back into the tunnel.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            for (route in parseJsonStrings(excludedRoutesJson)) {
                val (ip, prefix) = splitCidr(route) ?: continue
                try {
                    builder.excludeRoute(IpPrefix(InetAddress.getByName(ip), prefix))
                } catch (e: Exception) {
                    Log.w(TAG, "cannot exclude route $route", e)
                }
            }
        }

        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "cannot exclude own package", e)
        }

        val newPfd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        }
        if (newPfd == null) {
            failAndStop("Failed to establish VPN interface (permission revoked?)")
            return
        }

        val h = handle
        synchronized(tunLock) {
            closeTunLocked()
            pfd = newPfd
            tunOut = FileOutputStream(newPfd.fileDescriptor)
            val input = FileInputStream(newPfd.fileDescriptor)
            readThread = Thread({ readLoop(input, h) }, "mirage-tun-read").also { it.start() }
        }
    }

    private fun readLoop(input: FileInputStream, h: Long) {
        val buffer = ByteArray(32767)
        try {
            while (!Thread.currentThread().isInterrupted) {
                val n = input.read(buffer)
                if (n < 0) break
                if (n == 0) continue
                val keepGoing = handleLock.read {
                    if (handle != h) {
                        false
                    } else {
                        MirageNative.nativeSendPacket(h, buffer, n)
                        true
                    }
                }
                if (!keepGoing) break
            }
        } catch (_: IOException) {
            // fd closed during teardown
        } catch (t: Throwable) {
            Log.w(TAG, "tun read loop ended", t)
        }
    }

    private fun closeTun() = synchronized(tunLock) { closeTunLocked() }

    private fun closeTunLocked() {
        readThread?.interrupt()
        readThread = null
        tunOut = null
        try {
            pfd?.close()
        } catch (_: IOException) {
        }
        pfd = null
    }

    override fun onPacketWrite(packet: ByteArray) {
        synchronized(tunLock) {
            try {
                tunOut?.write(packet)
            } catch (_: IOException) {
                // TUN closed or being replaced; drop the packet.
            }
        }
    }

    override fun onStatusChange(status: Int, message: String?) {
        if (closing) return
        if (status == STATUS_DISCONNECTED && !sawActive) return
        if (status == STATUS_CONNECTING || status == STATUS_CONNECTED) sawActive = true

        MirageVpnService.status.value = status
        statusMessage.value = message

        when (status) {
            STATUS_CONNECTED -> updateNotification(getString(R.string.notification_connected))
            STATUS_DISCONNECTED, STATUS_ERROR -> post { teardown() }
        }
    }

    // ---------------------------------------------------------------- notification

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat_turbo)
            .setContentIntent(openApp)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun enterForeground(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    // ---------------------------------------------------------------- parsing helpers

    private fun parseJsonStrings(json: String): List<String> {
        if (json.isBlank()) return emptyList()
        return try {
            val array = JSONArray(json)
            (0 until array.length()).map { array.getString(it) }.filter { it.isNotBlank() }
        } catch (e: JSONException) {
            Log.w(TAG, "bad json array: $json", e)
            emptyList()
        }
    }

    /** Splits "a.b.c.d/nn" into (ip, prefix); a missing prefix means a host route. */
    private fun splitCidr(cidr: String): Pair<String, Int>? {
        val trimmed = cidr.trim()
        val slash = trimmed.indexOf('/')
        if (slash < 0) {
            return trimmed to (if (trimmed.contains(':')) 128 else 32)
        }
        val prefix = trimmed.substring(slash + 1).toIntOrNull() ?: return null
        return trimmed.substring(0, slash) to prefix
    }
}
