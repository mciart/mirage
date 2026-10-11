package com.mirage.vpn

import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.mirage.vpn.data.CodecResult
import com.mirage.vpn.ui.ImportParser
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real tunnel against a real server (CI starts one and passes an access link).
 *
 * Instrumentation arguments:
 *  - `e2eLink`       a mirage:// access link for the server under test (test is skipped without it)
 *  - `e2ePingTarget` address to ping through the tunnel (default 10.11.12.1)
 *
 * Flow: decode the link with the app's own import code -> grant VPN consent through appops ->
 * start MirageVpnService -> wait for CONNECTED -> ping from the shell (the app's own uid is
 * excluded from the VPN, the shell's is not) -> check the traffic counters -> disconnect.
 */
@RunWith(AndroidJUnit4::class)
class EndToEndVpnTest {

    private val instrumentation: Instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext

    private var toml: String = ""
    private var pingTarget: String = DEFAULT_PING_TARGET
    private var scenario: ActivityScenario<MainActivity>? = null
    private var consentGranted = false

    @Before
    fun setUp() {
        val args = InstrumentationRegistry.getArguments()
        val link = args.getString("e2eLink")?.trim().orEmpty()
        assumeTrue("e2eLink instrumentation argument not set; skipping the end-to-end test", link.isNotEmpty())
        pingTarget = args.getString("e2ePingTarget")?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_PING_TARGET

        // The app's own decode path (AccessLink + ConfigCodec). The link's routes are kept as they are.
        toml = when (val r = ImportParser.fromText(link)) {
            is CodecResult.Ok -> r.value.toml
            is CodecResult.Err -> throw AssertionError("The e2eLink could not be decoded: ${r.message}")
        }

        // Keep the app visible: starting a foreground service from the background can be refused.
        scenario = ActivityScenario.launch(MainActivity::class.java)

        // Pre-approve the VPN consent dialog for this app.
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        consentGranted = true

        // Start from a clean slate: the service state is process-wide and survives between tests.
        disconnectAndWait()
    }

    @After
    fun tearDown() {
        // Never leave the tunnel up, whatever happened (also runs when the test was skipped).
        disconnectAndWait()
        if (consentGranted) {
            shell("appops set ${context.packageName} ACTIVATE_VPN default")
            consentGranted = false
        }
        scenario?.close()
        scenario = null
    }

    @Test
    fun tunnelCarriesTraffic() {
        // 1. Connect.
        sendAction(MirageVpnService.ACTION_CONNECT, toml)
        val connected = waitFor(CONNECT_TIMEOUT_MS) {
            val s = MirageVpnService.status.value
            s == MirageVpnService.STATUS_CONNECTED || s == MirageVpnService.STATUS_ERROR
        }
        assertTrue(
            "VPN did not reach CONNECTED within ${CONNECT_TIMEOUT_MS / 1000}s. ${describeState()}",
            connected && MirageVpnService.status.value == MirageVpnService.STATUS_CONNECTED,
        )

        // 2. Ping through the tunnel as the shell user. The first replies can be lost while the
        //    tunnel settles, so give it a few rounds.
        val outputs = mutableListOf<String>()
        var received = 0
        for (attempt in 1..PING_ATTEMPTS) {
            val out = shell("ping -c 4 -W 3 $pingTarget")
            outputs += out
            received = parseReceived(out)
            if (received > 0) break
            assertTrue(
                "VPN dropped while pinging. ${describeState()}",
                MirageVpnService.status.value == MirageVpnService.STATUS_CONNECTED,
            )
        }
        assertTrue(
            "No ping replies from $pingTarget through the tunnel. ${describeState()}\n" +
                outputs.mapIndexed { i, o -> "--- attempt ${i + 1} ---\n$o" }.joinToString("\n"),
            received > 0,
        )

        // 3. The counters (polled once a second) must show traffic in both directions.
        val counted = waitFor(METRICS_TIMEOUT_MS) {
            val m = MirageVpnService.metrics.value
            m.size >= 2 && m[0] > 0 && m[1] > 0
        }
        assertTrue(
            "Metrics show no traffic (bytes sent/received = ${MirageVpnService.metrics.value.take(2)}). ${describeState()}",
            counted,
        )

        // 4. Disconnect cleanly.
        sendAction(MirageVpnService.ACTION_DISCONNECT)
        val down = waitFor(DISCONNECT_TIMEOUT_MS) {
            MirageVpnService.status.value == MirageVpnService.STATUS_DISCONNECTED && !MirageVpnService.isRunning.value
        }
        assertTrue("VPN did not disconnect. ${describeState()}", down)
    }

    // ---------------------------------------------------------------- helpers

    /** Disconnects if anything is running or left over (e.g. an ERROR state) and waits until it is gone. */
    private fun disconnectAndWait() {
        val idle = !MirageVpnService.isRunning.value &&
            MirageVpnService.status.value == MirageVpnService.STATUS_DISCONNECTED
        if (idle) return
        sendAction(MirageVpnService.ACTION_DISCONNECT)
        waitFor(DISCONNECT_TIMEOUT_MS) {
            !MirageVpnService.isRunning.value && MirageVpnService.status.value == MirageVpnService.STATUS_DISCONNECTED
        }
    }

    private fun sendAction(action: String, config: String? = null) {
        val intent = Intent(context, MirageVpnService::class.java).setAction(action)
        if (config != null) intent.putExtra(MirageVpnService.EXTRA_CONFIG, config)
        ContextCompat.startForegroundService(context, intent)
    }

    /** Runs a shell command as the shell user (uid 2000) and returns everything it printed. */
    private fun shell(command: String): String {
        val pfd: ParcelFileDescriptor = instrumentation.uiAutomation.executeShellCommand(command)
        return ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes().toString(Charsets.UTF_8) }
    }

    /** Number of echo replies in ping's summary line ("4 packets transmitted, 3 received, ..."). */
    private fun parseReceived(output: String): Int =
        Regex("""(\d+)\s+(?:packets\s+)?received""").find(output)?.groupValues?.get(1)?.toIntOrNull()
            ?: if (output.contains("bytes from")) 1 else 0

    private fun waitFor(timeoutMs: Long, condition: () -> Boolean): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (true) {
            if (condition()) return true
            if (SystemClock.elapsedRealtime() >= deadline) return false
            Thread.sleep(POLL_MS)
        }
    }

    private fun describeState(): String =
        "status=${MirageVpnService.status.value} message=${MirageVpnService.statusMessage.value ?: "(none)"} " +
            "protocol=${MirageVpnService.activeProtocol.value.ifEmpty { "(none)" }} running=${MirageVpnService.isRunning.value}"

    private companion object {
        const val DEFAULT_PING_TARGET = "10.11.12.1"
        const val CONNECT_TIMEOUT_MS = 90_000L
        const val METRICS_TIMEOUT_MS = 15_000L
        const val DISCONNECT_TIMEOUT_MS = 30_000L
        const val POLL_MS = 500L
        const val PING_ATTEMPTS = 3
    }
}
