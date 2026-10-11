package com.mirage.vpn.data

/** Builds the minimal client config used by "Sign in with username" on public builds. */
object SignInConfig {
    /**
     * Minimal TOML for a username / password sign-in. Every other option takes the Rust default,
     * so the result is meant to be run through `nativeParseConfig` (which fills them in).
     * `[log]` is required by the Rust parser.
     */
    fun toml(host: String, port: Int, username: String, password: String): String = """
[server]
host = ${tomlString(host)}
port = $port

[authentication]
username = ${tomlString(username)}
password = ${tomlString(password)}

[transport]
protocols = ["udp", "tcp"]

[network]
routes = ["0.0.0.0/0", "::/0"]
dns_servers = ["1.1.1.1"]

[log]
level = "info"
""".trimStart()

    /** TOML basic string (double-quoted) with everything that needs escaping escaped. */
    fun tomlString(value: String): String = buildString {
        append('"')
        for (c in value) {
            when {
                c == '"' -> append("\\\"")
                c == '\\' -> append("\\\\")
                c == '\n' -> append("\\n")
                c == '\r' -> append("\\r")
                c == '\t' -> append("\\t")
                c.code < 0x20 || c.code == 0x7F -> append("\\u").append(String.format("%04X", c.code))
                else -> append(c)
            }
        }
        append('"')
    }
}
