package com.mirage.vpn.data

/** Pure-Kotlin IP / CIDR checks (no DNS lookups, safe on the main thread). */
object NetValidation {
    fun parseList(text: String): List<String> =
        text.split(Regex("[,\\s]+")).filter { it.isNotEmpty() }

    fun isIpv4(s: String): Boolean {
        val parts = s.split('.')
        if (parts.size != 4) return false
        return parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && p.toInt() in 0..255
        }
    }

    fun isIpv6(s: String): Boolean {
        if (s.isEmpty() || s.contains(":::")) return false
        if (s.any { !(it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.') }) return false
        val dbl = s.indexOf("::")
        if (dbl >= 0 && s.indexOf("::", dbl + 1) >= 0) return false

        // Number of 16-bit groups in a ':'-separated part, or -1 if invalid.
        fun count(part: String, mayEndWithV4: Boolean): Int {
            if (part.isEmpty()) return 0
            val groups = part.split(':')
            var n = 0
            for ((i, g) in groups.withIndex()) {
                if (g.contains('.')) {
                    if (!(mayEndWithV4 && i == groups.lastIndex && isIpv4(g))) return -1
                    n += 2
                } else {
                    if (g.isEmpty() || g.length > 4) return -1
                    n += 1
                }
            }
            return n
        }

        if (dbl < 0) return count(s, true) == 8
        val head = count(s.substring(0, dbl), false)
        val tail = count(s.substring(dbl + 2), true)
        return head >= 0 && tail >= 0 && head + tail <= 7
    }

    fun isIp(s: String): Boolean = isIpv4(s) || isIpv6(s)

    fun isCidr(s: String): Boolean {
        val parts = s.split('/')
        if (parts.size != 2) return false
        val ip = parts[0]
        val prefix = parts[1]
        if (prefix.isEmpty() || prefix.length > 3 || !prefix.all { it in '0'..'9' }) return false
        val p = prefix.toInt()
        return when {
            isIpv4(ip) -> p in 0..32
            isIpv6(ip) -> p in 0..128
            else -> false
        }
    }
}
