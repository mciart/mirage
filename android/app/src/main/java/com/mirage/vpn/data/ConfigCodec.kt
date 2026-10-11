package com.mirage.vpn.data

import com.mirage.vpn.MirageNative
import org.json.JSONObject

/** Result of a codec / decoder step: either a value or a human-readable error. */
sealed interface CodecResult<out T> {
    data class Ok<T>(val value: T) : CodecResult<T>
    data class Err(val message: String) : CodecResult<Nothing>
}

/**
 * Kotlin wrapper over the JSON-envelope JNI helpers. Never throws: a missing native library
 * (or any other failure) is reported as [CodecResult.Err].
 */
object ConfigCodec {
    private const val NO_NATIVE = "The VPN core library isn't available on this device."

    /** TOML -> fully resolved ClientConfig JSON (defaults filled in by the Rust parser). */
    fun parse(toml: String): CodecResult<JSONObject> {
        val ok = envelope { MirageNative.nativeParseConfig(toml) }
        return when (ok) {
            is CodecResult.Err -> ok
            is CodecResult.Ok -> {
                val v = ok.value
                if (v is JSONObject) CodecResult.Ok(v)
                else CodecResult.Err("Unexpected response from the core library.")
            }
        }
    }

    /** ClientConfig JSON -> TOML. */
    fun toToml(json: JSONObject): CodecResult<String> {
        val text = json.toString()
        val ok = envelope { MirageNative.nativeConfigToToml(text) }
        return when (ok) {
            is CodecResult.Err -> ok
            is CodecResult.Ok -> {
                val v = ok.value
                if (v is String) CodecResult.Ok(v)
                else CodecResult.Err("Unexpected response from the core library.")
            }
        }
    }

    private fun envelope(call: () -> String): CodecResult<Any> {
        val raw = try {
            call()
        } catch (e: LinkageError) {
            // UnsatisfiedLinkError, ExceptionInInitializerError, NoClassDefFoundError
            return CodecResult.Err(NO_NATIVE)
        } catch (e: Exception) {
            return CodecResult.Err(e.message ?: "Unexpected error in the core library.")
        }
        return try {
            val env = JSONObject(raw)
            if (env.has("error") && !env.isNull("error")) {
                CodecResult.Err(env.optString("error", "Unknown error"))
            } else {
                val v = env.opt("ok")
                if (v == null || v === JSONObject.NULL) CodecResult.Err("Empty response from the core library.")
                else CodecResult.Ok(v)
            }
        } catch (e: Exception) {
            CodecResult.Err("Unreadable response from the core library.")
        }
    }
}
