package com.mirage.vpn.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.mirage.vpn.data.CodecResult
import com.mirage.vpn.data.ConfigCodec
import com.mirage.vpn.data.NetValidation
import com.mirage.vpn.data.Profile
import org.json.JSONArray
import org.json.JSONObject

private fun JSONObject?.str(key: String, def: String = ""): String =
    if (this == null || isNull(key)) def else optString(key, def)

private fun JSONObject?.bool(key: String, def: Boolean): Boolean =
    if (this == null || isNull(key)) def else optBoolean(key, def)

private fun JSONObject?.num(key: String, def: String): String =
    if (this == null || isNull(key)) def else (opt(key)?.toString() ?: def)

private fun JSONObject?.strings(key: String): List<String> {
    val arr = this?.optJSONArray(key) ?: return emptyList()
    return List(arr.length()) { arr.optString(it) }
}

private fun JSONObject.section(name: String): JSONObject =
    optJSONObject(name) ?: JSONObject().also { put(name, it) }

private fun JSONObject.putLong(key: String, text: String) {
    val v = text.trim().toLongOrNull()
    if (v != null) put(key, v)
}

private fun JSONObject.putOptional(key: String, text: String) {
    val t = text.trim()
    if (t.isEmpty()) put(key, JSONObject.NULL) else put(key, t)
}

/**
 * Editable view of a ClientConfig JSON. Every field maps to one key path; [applyTo] writes the
 * fields back into an existing JSONObject IN PLACE so that keys this form doesn't know about
 * (e.g. options added to the Rust core later, `network.interface_name`, `trusted_certificate_paths`)
 * survive untouched.
 *
 * Error keys: basics use a bare id ("host"); advanced fields use "<section>/<field>".
 */
class ServerForm {
    // Basics: server.host, server.port, authentication.username, authentication.password
    var host by mutableStateOf("")
    var port by mutableStateOf("443")
    var username by mutableStateOf("")
    var password by mutableStateOf("")

    // Connection: transport.protocols ("keep" = leave the config's own list, e.g. ["tcp","udp"])
    var protocol by mutableStateOf("auto")

    // Disguise: camouflage.*
    var camoMode by mutableStateOf("mirage")
    var targetSni by mutableStateOf("")
    var shortIds by mutableStateOf("")
    var jlsPassword by mutableStateOf("")
    var jlsIv by mutableStateOf("")
    var innerKey by mutableStateOf("")

    // Transport: transport.*
    var parallel by mutableStateOf("1")
    var dualStack by mutableStateOf(false)
    var customSni by mutableStateOf("")
    var insecure by mutableStateOf(false)
    var tcpNodelay by mutableStateOf(true)
    var hopping by mutableStateOf("0")

    // Connection: connection.*
    var mtu by mutableStateOf("1280")
    var outerMtu by mutableStateOf("1420")
    var timeout by mutableStateOf("30")
    var retry by mutableStateOf("5")
    var keepAlive by mutableStateOf("25")
    var sendBuf by mutableStateOf("2097152")
    var recvBuf by mutableStateOf("2097152")
    var connNodelay by mutableStateOf(true)
    var reuseSocket by mutableStateOf(false)
    var maxLifetime by mutableStateOf("300")
    var lifetimeJitter by mutableStateOf("60")
    var muxMode by mutableStateOf("round_robin")

    // Obfuscation: obfuscation.*
    var obfEnabled by mutableStateOf(true)
    var padProb by mutableStateOf("0.15")
    var padMin by mutableStateOf("40")
    var padMax by mutableStateOf("1200")
    var jitterMin by mutableStateOf("0")
    var jitterMax by mutableStateOf("0")
    var tlsPadding by mutableStateOf(false)
    var innerEncryption by mutableStateOf(false)

    // Network: network.routes / excluded_routes / dns_servers (one per line), static_client_ip(_v6)
    var routes by mutableStateOf("")
    var excluded by mutableStateOf("")
    var dns by mutableStateOf("")
    var staticIp by mutableStateOf("")
    var staticIpV6 by mutableStateOf("")

    // Certificates: authentication.trusted_certificates (PEM blocks)
    var certs by mutableStateOf("")

    // Logging: log.level
    var logLevel by mutableStateOf("info")

    val errors = mutableStateMapOf<String, String>()

    /** Non-default routes remembered while "Send all traffic" is on, to restore when it's turned off. */
    private var privateRoutes: List<String> = emptyList()

    val allTraffic: Boolean get() = NetValidation.parseList(routes).contains("0.0.0.0/0")

    /**
     * "Send all traffic through VPN" toggle.
     *  on  -> routes = ["0.0.0.0/0", "::/0"] (remembering any private routes the config had)
     *  off -> keep/restore the config's own non-default routes. If it never had any we can't know
     *         the server's private network, so fall back to the Mirage default tunnel network
     *         (the one in examples/client.toml) rather than routing nothing.
     */
    fun setAllTraffic(on: Boolean) {
        val current = NetValidation.parseList(routes)
        val own = current.filter { it !in ALL_ROUTES }
        if (on) {
            if (own.isNotEmpty()) privateRoutes = own
            routes = ALL_ROUTES.joinToString("\n")
        } else {
            routes = own.ifEmpty { privateRoutes }.ifEmpty { DEFAULT_PRIVATE_ROUTES }.joinToString("\n")
        }
        errors.remove("network/routes")
    }

    fun setDisguise(on: Boolean) {
        camoMode = if (on) (if (camoMode != "none" && camoMode.isNotBlank()) camoMode else "mirage") else "none"
    }

    fun loadFrom(json: JSONObject) {
        val server = json.optJSONObject("server")
        host = server.str("host")
        port = server.num("port", "443")

        val auth = json.optJSONObject("authentication")
        username = auth.str("username")
        password = auth.str("password")
        certs = auth.strings("trusted_certificates").joinToString("\n\n")

        val tr = json.optJSONObject("transport")
        val protos = if (tr?.has("protocols") == true) tr.strings("protocols") else listOf("udp", "tcp")
        protocol = when (protos) {
            listOf("udp", "tcp") -> "auto"
            listOf("udp") -> "udp"
            listOf("tcp") -> "tcp"
            else -> "keep"
        }
        parallel = tr.num("parallel_connections", "1")
        dualStack = tr.bool("dual_stack", false)
        customSni = tr.str("sni")
        insecure = tr.bool("insecure", false)
        tcpNodelay = tr.bool("tcp_nodelay", true)
        hopping = tr.num("port_hopping_interval_s", "0")

        val con = json.optJSONObject("connection")
        mtu = con.num("mtu", "1280")
        outerMtu = con.num("outer_mtu", "1420")
        timeout = con.num("timeout_s", "30")
        retry = con.num("retry_interval_s", "5")
        keepAlive = con.num("keep_alive_interval_s", "25")
        sendBuf = con.num("send_buffer_size", "2097152")
        recvBuf = con.num("recv_buffer_size", "2097152")
        connNodelay = con.bool("tcp_nodelay", true)
        reuseSocket = con.bool("reuse_socket", false)
        maxLifetime = con.num("max_lifetime_s", "300")
        lifetimeJitter = con.num("lifetime_jitter_s", "60")
        muxMode = con.str("mux_mode", "round_robin")

        val obf = json.optJSONObject("obfuscation")
        obfEnabled = obf.bool("enabled", true)
        padProb = obf.num("padding_probability", "0.15")
        padMin = obf.num("padding_min", "40")
        padMax = obf.num("padding_max", "1200")
        jitterMin = obf.num("jitter_min_ms", "0")
        jitterMax = obf.num("jitter_max_ms", "0")
        tlsPadding = obf.bool("tls_record_padding", false)
        innerEncryption = obf.bool("inner_encryption", false)

        val net = json.optJSONObject("network")
        val r = net.strings("routes")
        routes = r.joinToString("\n")
        privateRoutes = r.filter { it !in ALL_ROUTES }
        excluded = net.strings("excluded_routes").joinToString("\n")
        dns = net.strings("dns_servers").joinToString("\n")
        staticIp = json.str("static_client_ip")
        staticIpV6 = json.str("static_client_ip_v6")

        val camo = json.optJSONObject("camouflage")
        camoMode = camo.str("mode", "mirage")
        targetSni = camo.str("target_sni")
        shortIds = camo.strings("short_ids").joinToString("\n")
        jlsPassword = camo.str("jls_password")
        jlsIv = camo.str("jls_iv")
        innerKey = camo.str("inner_key")

        logLevel = json.optJSONObject("log").str("level", "info")
    }

    /** Starting point for a brand-new server: blank identity, sensible network defaults. */
    fun applyNewServerDefaults() {
        host = ""
        port = "443"
        username = ""
        password = ""
        shortIds = ""
        if (dns.isBlank()) dns = "1.1.1.1\n2606:4700:4700::1111"
        setAllTraffic(true)
    }

    /** Writes every field into [json] in place. Unparseable numbers are skipped (see [validate]). */
    fun applyTo(json: JSONObject) {
        json.section("server").apply {
            put("host", host.trim())
            if (port.isBlank()) put("port", 443) else putLong("port", port)
        }
        json.section("authentication").apply {
            put("username", username.trim())
            put("password", password)
            put("trusted_certificates", JSONArray(pemBlocks(certs)))
        }
        json.section("transport").apply {
            val protos = when (protocol) {
                "auto" -> listOf("udp", "tcp")
                "udp" -> listOf("udp")
                "tcp" -> listOf("tcp")
                else -> null // "keep": untouched
            }
            if (protos != null) put("protocols", JSONArray(protos))
            putLong("parallel_connections", parallel)
            put("dual_stack", dualStack)
            putOptional("sni", customSni)
            put("insecure", insecure)
            put("tcp_nodelay", tcpNodelay)
            putLong("port_hopping_interval_s", hopping)
        }
        json.section("connection").apply {
            putLong("mtu", mtu)
            putLong("outer_mtu", outerMtu)
            putLong("timeout_s", timeout)
            putLong("retry_interval_s", retry)
            putLong("keep_alive_interval_s", keepAlive)
            putLong("send_buffer_size", sendBuf)
            putLong("recv_buffer_size", recvBuf)
            put("tcp_nodelay", connNodelay)
            put("reuse_socket", reuseSocket)
            putLong("max_lifetime_s", maxLifetime)
            putLong("lifetime_jitter_s", lifetimeJitter)
            put("mux_mode", muxMode)
        }
        json.section("obfuscation").apply {
            put("enabled", obfEnabled)
            padProb.trim().toDoubleOrNull()?.let { put("padding_probability", it) }
            putLong("padding_min", padMin)
            putLong("padding_max", padMax)
            putLong("jitter_min_ms", jitterMin)
            putLong("jitter_max_ms", jitterMax)
            put("tls_record_padding", tlsPadding)
            put("inner_encryption", innerEncryption)
        }
        json.section("network").apply {
            put("routes", JSONArray(NetValidation.parseList(routes)))
            put("excluded_routes", JSONArray(NetValidation.parseList(excluded)))
            put("dns_servers", JSONArray(NetValidation.parseList(dns)))
            // interface_name and any unknown keys are deliberately left alone.
        }
        json.section("camouflage").apply {
            put("mode", camoMode)
            put("target_sni", targetSni.trim())
            put("short_ids", JSONArray(NetValidation.parseList(shortIds)))
            putOptional("jls_password", jlsPassword)
            putOptional("jls_iv", jlsIv)
            putOptional("inner_key", innerKey)
        }
        json.section("log").put("level", logLevel)
        json.putOptional("static_client_ip", staticIp)
        json.putOptional("static_client_ip_v6", staticIpV6)
    }

    /** Live TOML for the "Config file" section. */
    fun previewToml(base: JSONObject): CodecResult<String> {
        val copy = JSONObject(base.toString())
        applyTo(copy)
        return ConfigCodec.toToml(copy)
    }

    /**
     * Full save pipeline: apply to a copy of [base] -> nativeConfigToToml -> nativeParseConfig on
     * that TOML (the real Rust parser validates it) -> Profile. The stored JSON is the edited copy
     * (not the re-parsed one) so unknown keys survive.
     */
    fun buildProfile(base: JSONObject, existing: Profile?): CodecResult<Profile> {
        val json = JSONObject(base.toString())
        applyTo(json)
        val toml = when (val t = ConfigCodec.toToml(json)) {
            is CodecResult.Err -> return t
            is CodecResult.Ok -> t.value
        }
        when (val p = ConfigCodec.parse(toml)) {
            is CodecResult.Err -> return p
            is CodecResult.Ok -> Unit
        }
        val h = host.trim()
        val name = existing?.name?.takeIf { it.isNotBlank() && it != existing?.host } ?: h
        return CodecResult.Ok(Profile(name, json, toml))
    }

    /** Sections (keys before '/') that contain errors, so the editor can expand them. */
    fun sectionsWithErrors(): Set<String> =
        errors.keys.filter { '/' in it }.map { it.substringBefore('/') }.toSet()

    fun validate(): Boolean {
        errors.clear()

        val h = host.trim()
        if (h.isEmpty()) errors["host"] = "Enter the server address"
        else if (h.any { it.isWhitespace() } || h.contains("://")) errors["host"] = "Use just the address, like vpn.example.com"
        range("port", port, 1, 65535, blankOk = true)
        if (username.isBlank()) errors["username"] = "Enter your username"
        if (password.isEmpty()) errors["password"] = "Enter your password"

        // Disguise
        if (targetSni.any { it.isWhitespace() }) errors["disguise/targetSni"] = "No spaces, like www.example.com"
        if (NetValidation.parseList(shortIds).any { id -> !id.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } }) {
            errors["disguise/shortIds"] = "Hex digits only (0-9, a-f), one per line"
        }

        // Transport
        range("transport/parallel", parallel, 1, 4)
        if (customSni.any { it.isWhitespace() }) errors["transport/customSni"] = "No spaces, like www.example.com"
        range("transport/hopping", hopping, 0, 86_400)

        // Connection
        range("connection/mtu", mtu, 576, 65_535)
        range("connection/outerMtu", outerMtu, 576, 65_535)
        range("connection/timeout", timeout, 1, 86_400)
        range("connection/retry", retry, 1, 86_400)
        range("connection/keepAlive", keepAlive, 0, 86_400)
        range("connection/sendBuf", sendBuf, 1, 1_073_741_824)
        range("connection/recvBuf", recvBuf, 1, 1_073_741_824)
        range("connection/maxLifetime", maxLifetime, 0, 604_800)
        range("connection/lifetimeJitter", lifetimeJitter, 0, 604_800)

        // Obfuscation
        val p = padProb.trim().toDoubleOrNull()
        if (p == null || p < 0.0 || p > 1.0) errors["obfuscation/padProb"] = "0–1"
        range("obfuscation/padMin", padMin, 0, 65_535)
        range("obfuscation/padMax", padMax, 0, 65_535)
        range("obfuscation/jitterMin", jitterMin, 0, 10_000)
        range("obfuscation/jitterMax", jitterMax, 0, 10_000)
        minMax("obfuscation/padMax", padMin, padMax)
        minMax("obfuscation/jitterMax", jitterMin, jitterMax)

        // Network
        listCheck("network/routes", routes, "network like 10.0.0.0/8", NetValidation::isCidr)
        listCheck("network/excluded", excluded, "network like 192.168.0.0/16", NetValidation::isCidr)
        listCheck("network/dns", dns, "IP address like 1.1.1.1", NetValidation::isIp)
        if (staticIp.isNotBlank() && !NetValidation.isIp(staticIp.trim())) errors["network/staticIp"] = "Not a valid IP address"
        if (staticIpV6.isNotBlank() && !NetValidation.isIp(staticIpV6.trim())) errors["network/staticIpV6"] = "Not a valid IP address"

        // Certificates
        if (certs.isNotBlank() && pemBlocks(certs).isEmpty()) {
            errors["certs/pem"] = "Paste PEM certificates (-----BEGIN CERTIFICATE----- …)"
        }
        return errors.isEmpty()
    }

    private fun range(key: String, text: String, min: Long, max: Long, blankOk: Boolean = false) {
        val t = text.trim()
        if (t.isEmpty()) {
            if (!blankOk) errors[key] = "Required"
            return
        }
        val v = t.toLongOrNull()
        if (v == null || v < min || v > max) errors[key] = "$min–$max"
    }

    private fun minMax(key: String, min: String, max: String) {
        if (key in errors) return
        val a = min.trim().toLongOrNull() ?: return
        val b = max.trim().toLongOrNull() ?: return
        if (b < a) errors[key] = "Must not be below the minimum"
    }

    private fun listCheck(key: String, text: String, what: String, ok: (String) -> Boolean) {
        val bad = NetValidation.parseList(text).firstOrNull { !ok(it) } ?: return
        errors[key] = "\"$bad\" is not a valid $what"
    }

    companion object {
        val ALL_ROUTES = listOf("0.0.0.0/0", "::/0")
        val DEFAULT_PRIVATE_ROUTES = listOf("10.11.12.0/24", "fd00::/64")
        private val PEM = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")

        fun pemBlocks(text: String): List<String> =
            PEM.findAll(text).map { m ->
                // Normalise line endings / indentation from pasted text.
                m.value.lines().joinToString("\n") { it.trim() }
            }.toList()
    }
}
