package com.mirage.vpn

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.mirage.vpn.data.AccessLink
import com.mirage.vpn.data.CodecResult
import com.mirage.vpn.data.ConfigCodec
import com.mirage.vpn.data.SignInConfig
import com.mirage.vpn.ui.ImportParser
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Talks to the real libmirage_ffi.so on the device/emulator: config parsing, the TOML round-trip,
 * handle creation, and the access-link codec.
 */
@RunWith(AndroidJUnit4::class)
class NativeCoreTest {

    private val sampleToml = """
        [server]
        host = "vpn.example.com"
        port = 8443

        [authentication]
        username = "alice"
        password = "s3cret"

        [transport]
        protocols = ["udp", "tcp"]

        [network]
        routes = ["10.11.12.0/24", "fd00::/64"]
        dns_servers = ["1.1.1.1"]

        [camouflage]
        mode = "mirage"
        target_sni = "www.microsoft.com"
        short_ids = ["abcd1234deadbeef"]

        [log]
        level = "info"
    """.trimIndent()

    /** The raw JNI envelope: {"ok": ...} or {"error": "..."}. */
    private fun parseEnvelope(toml: String): JSONObject = JSONObject(MirageNative.nativeParseConfig(toml))

    @Test
    fun nativeLibraryLoads() {
        // Touching MirageNative runs its initializer, which calls System.loadLibrary("mirage_ffi").
        assertNotNull(MirageNative.nativeLastError())
    }

    @Test
    fun parseConfigReturnsResolvedConfig() {
        val env = parseEnvelope(sampleToml)
        assertTrue("expected an ok envelope but got: $env", env.has("ok") && !env.has("error"))
        val config = env.getJSONObject("ok")
        assertEquals("vpn.example.com", config.getJSONObject("server").getString("host"))
        assertEquals(8443, config.getJSONObject("server").getInt("port"))
        assertEquals("alice", config.getJSONObject("authentication").getString("username"))
        assertEquals("s3cret", config.getJSONObject("authentication").getString("password"))
        assertEquals(
            listOf("udp", "tcp"),
            config.getJSONObject("transport").getJSONArray("protocols").toStringList(),
        )
        // Defaults the TOML didn't mention are filled in by the Rust parser.
        assertTrue(config.getJSONObject("connection").has("mtu"))
        assertEquals("info", config.getJSONObject("log").getString("level"))
    }

    @Test
    fun configRoundTripsThroughToml() {
        val first = parseEnvelope(sampleToml).getJSONObject("ok")

        val tomlEnv = JSONObject(MirageNative.nativeConfigToToml(first.toString()))
        assertTrue("expected an ok envelope but got: $tomlEnv", tomlEnv.has("ok") && !tomlEnv.has("error"))
        val toml = tomlEnv.getString("ok")
        assertTrue("TOML should name the server", toml.contains("vpn.example.com"))

        val second = parseEnvelope(toml).getJSONObject("ok")
        assertJsonEquals("config changed after nativeConfigToToml -> nativeParseConfig", first, second)
    }

    @Test
    fun invalidTomlGivesErrorEnvelope() {
        val garbage = parseEnvelope("this is = = not [valid toml")
        assertTrue("expected an error envelope but got: $garbage", garbage.has("error") && !garbage.has("ok"))
        assertTrue(garbage.getString("error").isNotBlank())

        // Valid TOML, but not a valid client config (no [server] / [authentication] / [log]).
        val incomplete = parseEnvelope("[server]\nhost = \"x\"\n")
        assertTrue("expected an error envelope but got: $incomplete", incomplete.has("error") && !incomplete.has("ok"))

        // The Kotlin wrapper reports the same thing as a CodecResult.Err instead of throwing.
        assertTrue(ConfigCodec.parse("this is = = not [valid toml") is CodecResult.Err)
    }

    @Test
    fun createAndDestroyHandle() {
        val handle = MirageNative.nativeCreate(sampleToml)
        assertNotEquals("nativeCreate failed: ${MirageNative.nativeLastError()}", 0L, handle)
        try {
            // A freshly created (not started) runtime reports DISCONNECTED and empty metrics.
            assertEquals(MirageVpnService.STATUS_DISCONNECTED, MirageNative.nativeGetStatus(handle))
            assertTrue(MirageNative.nativeGetMetrics(handle).size >= 5)
        } finally {
            MirageNative.nativeDestroy(handle)
        }
    }

    @Test
    fun createRejectsInvalidConfig() {
        val handle = MirageNative.nativeCreate("not a config")
        if (handle != 0L) {
            MirageNative.nativeDestroy(handle)
            fail("nativeCreate accepted an invalid config")
        }
        assertTrue(MirageNative.nativeLastError().isNotBlank())
    }

    @Test
    fun accessLinkRoundTrips() {
        val link = AccessLink.encode("Café & Co", sampleToml)
        assertTrue(link, link.startsWith("mirage://import?v=1&name="))

        val decoded = AccessLink.decode(link).okOrFail("AccessLink.decode")
        assertEquals("Café & Co", decoded.name)
        assertEquals(sampleToml, decoded.toml)

        // Links pasted inside other text are found.
        assertEquals(link, AccessLink.find("Here is your link: $link thanks"))
    }

    @Test
    fun importParserAcceptsLinkAndRawToml() {
        val link = AccessLink.encode("Office", sampleToml)

        val fromLink = ImportParser.fromText(link).okOrFail("import of an access link")
        assertEquals("Office", fromLink.name)
        assertEquals("vpn.example.com", fromLink.host)
        assertEquals(8443, fromLink.port)
        assertTrue(fromLink.fromLink)

        val fromToml = ImportParser.fromText(sampleToml).okOrFail("import of raw TOML")
        assertEquals("vpn.example.com", fromToml.name) // no name in raw TOML: falls back to the host
        assertFalse(fromToml.fromLink)

        assertTrue(ImportParser.fromText("   ") is CodecResult.Err)
        assertTrue(ImportParser.fromText("mirage://import?v=2&config=AAAA") is CodecResult.Err)
    }

    @Test
    fun signInConfigParsesAndEscapesSecrets() {
        // Quotes, backslashes and non-ASCII must survive the minimal TOML we generate.
        val password = "p\"a\\ss wörd #1"
        val toml = SignInConfig.toml("vpn.example.com", 443, "sara", password)

        val config = ConfigCodec.parse(toml).okOrFail("minimal sign-in TOML")
        assertEquals("vpn.example.com", config.getJSONObject("server").getString("host"))
        assertEquals(443, config.getJSONObject("server").getInt("port"))
        assertEquals("sara", config.getJSONObject("authentication").getString("username"))
        assertEquals(password, config.getJSONObject("authentication").getString("password"))
        assertEquals(listOf("udp", "tcp"), config.getJSONObject("transport").getJSONArray("protocols").toStringList())
        assertEquals(
            listOf("0.0.0.0/0", "::/0"),
            config.getJSONObject("network").getJSONArray("routes").toStringList(),
        )
        assertEquals(listOf("1.1.1.1"), config.getJSONObject("network").getJSONArray("dns_servers").toStringList())
    }

    // ---------------------------------------------------------------- helpers

    private fun <T> CodecResult<T>.okOrFail(what: String): T = when (this) {
        is CodecResult.Ok -> value
        is CodecResult.Err -> throw AssertionError("$what failed: $message")
    }

    private fun JSONArray.toStringList(): List<String> = List(length()) { getString(it) }

    /** org.json on Android has no structural equals(), so compare trees by hand. */
    private fun assertJsonEquals(message: String, expected: Any?, actual: Any?, path: String = "$") {
        when {
            expected is JSONObject && actual is JSONObject -> {
                val keys = expected.keys().asSequence().toSet() + actual.keys().asSequence().toSet()
                for (key in keys.sorted()) {
                    assertTrue("$message: key $path.$key missing on one side", expected.has(key) && actual.has(key))
                    assertJsonEquals(message, expected.get(key), actual.get(key), "$path.$key")
                }
            }
            expected is JSONArray && actual is JSONArray -> {
                assertEquals("$message: length of $path", expected.length(), actual.length())
                for (i in 0 until expected.length()) {
                    assertJsonEquals(message, expected.get(i), actual.get(i), "$path[$i]")
                }
            }
            expected is Number && actual is Number ->
                assertEquals("$message: $path", expected.toDouble(), actual.toDouble(), 1e-9)
            else -> assertEquals("$message: $path", expected, actual)
        }
    }
}
