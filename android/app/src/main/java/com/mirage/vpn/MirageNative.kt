package com.mirage.vpn

interface MirageCallback {
    // Rust -> Kotlin: an outbound IP packet to write to the TUN fd.
    fun onPacketWrite(packet: ByteArray)

    // Rust -> Kotlin: status change. status: 0=DISCONNECTED,1=CONNECTING,2=CONNECTED,3=ERROR.
    fun onStatusChange(status: Int, message: String?)

    // Rust -> Kotlin: tunnel params after auth. Kotlin builds the VpnService TUN from these.
    // *Json fields are JSON string arrays, e.g. ["1.1.1.1"], ["0.0.0.0/0","::/0"].
    // clientAddress / clientAddressV6 are CIDR like "10.11.12.13/24" (v6 may be "").
    fun onTunnelConfig(
        clientAddress: String,
        clientAddressV6: String,
        mtu: Int,
        dnsServersJson: String,
        routesJson: String,
        excludedRoutesJson: String,
    )
}

object MirageNative {
    init {
        System.loadLibrary("mirage_ffi")
    }

    // Returns a non-zero handle (as Long) on success, 0 on failure.
    // On failure, nativeLastError() returns the message.
    external fun nativeCreate(configToml: String): Long
    external fun nativeLastError(): String

    // Starts the connection asynchronously; callbacks fire on a background thread.
    external fun nativeStart(handle: Long, callback: MirageCallback)

    // Kotlin -> Rust: deliver an inbound packet read from the TUN fd. Returns true if queued.
    external fun nativeSendPacket(handle: Long, packet: ByteArray, len: Int): Boolean

    external fun nativeStop(handle: Long)
    external fun nativeDestroy(handle: Long)

    // 0=DISCONNECTED,1=CONNECTING,2=CONNECTED,3=ERROR
    external fun nativeGetStatus(handle: Long): Int

    // Returns [bytesSent, bytesReceived, packetsSent, packetsReceived, uptimeSeconds]
    external fun nativeGetMetrics(handle: Long): LongArray
    external fun nativeGetActiveProtocol(handle: Long): String

    // Config helpers. Both return a JSON envelope: {"ok": <value>} or {"error": "<message>"}.
    // nativeParseConfig: TOML -> fully resolved ClientConfig as a JSON object.
    external fun nativeParseConfig(toml: String): String

    // nativeConfigToToml: ClientConfig JSON object -> TOML string.
    external fun nativeConfigToToml(json: String): String
}
