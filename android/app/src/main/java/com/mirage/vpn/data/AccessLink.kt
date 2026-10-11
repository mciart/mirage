package com.mirage.vpn.data

import android.net.Uri
import android.util.Base64

/**
 * Access link: mirage://import?v=1&name=<percent-encoded>&config=<base64url, no padding, TOML>
 */
object AccessLink {
    data class Decoded(val name: String?, val toml: String)

    private val LINK_REGEX = Regex("mirage://\\S+", RegexOption.IGNORE_CASE)

    /** Finds a mirage:// link inside arbitrary pasted text, or null. */
    fun find(text: String): String? = LINK_REGEX.find(text)?.value

    fun decode(link: String): CodecResult<Decoded> {
        val uri = try {
            Uri.parse(link.trim())
        } catch (e: Exception) {
            return CodecResult.Err("This isn't a valid Turbo VPN link.")
        }
        if (!"mirage".equals(uri.scheme, ignoreCase = true) || !"import".equals(uri.host, ignoreCase = true)) {
            return CodecResult.Err("This isn't a Turbo VPN link.")
        }
        val version = uri.getQueryParameter("v")?.trim()
        when {
            version == null -> return CodecResult.Err("This link has no version number, so it can't be read.")
            version != "1" -> {
                val n = version.toIntOrNull()
                return CodecResult.Err(
                    if (n != null && n > 1) "This link was made by a newer version of Turbo VPN (link version $version). Update the app and try again."
                    else "Unsupported link version \"$version\".",
                )
            }
        }
        // Uri decodes '+' as a space; in standard-alphabet base64 that '+' is data, so restore it.
        val rawConfig = uri.getQueryParameter("config")?.replace(' ', '+')
        if (rawConfig.isNullOrBlank()) return CodecResult.Err("This link doesn't contain a configuration.")
        val bytes = decodeBase64(rawConfig) ?: return CodecResult.Err("The configuration in this link is damaged.")
        val toml = String(bytes, Charsets.UTF_8)
        if (toml.isBlank()) return CodecResult.Err("This link doesn't contain a configuration.")
        val name = uri.getQueryParameter("name")?.trim()?.takeIf { it.isNotEmpty() }
        return CodecResult.Ok(Decoded(name, toml))
    }

    fun encode(name: String, toml: String): String {
        val b64 = Base64.encodeToString(
            toml.toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE,
        )
        return "mirage://import?v=1&name=${Uri.encode(name)}&config=$b64"
    }

    /** Lenient base64: URL-safe or standard alphabet, padded or not, whitespace ignored. */
    fun decodeBase64(input: String): ByteArray? {
        val cleaned = input.filter { !it.isWhitespace() }
            .replace('-', '+')
            .replace('_', '/')
            .trimEnd('=')
        val padded = when (cleaned.length % 4) {
            0 -> cleaned
            2 -> "$cleaned=="
            3 -> "$cleaned="
            else -> return null
        }
        return try {
            Base64.decode(padded, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
