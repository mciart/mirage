package com.mirage.vpn

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.mirage.vpn.data.ProfileStore
import com.mirage.vpn.ui.Tags
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Drives the real UI on MainActivity: welcome screen, sign-in validation, sign-in to home, and
 * removing the server again. The stored profile is cleared before every test (before the
 * activity starts, so the view model never sees a leftover profile).
 */
@RunWith(AndroidJUnit4::class)
class AppSmokeTest {

    // The activity is launched by hand in setUp() so the profile can be cleared first.
    @get:Rule
    val compose = createEmptyComposeRule()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private var scenario: ActivityScenario<MainActivity>? = null

    @Before
    fun setUp() {
        // A private build (built-in server) starts on the sign-in screen instead of the welcome screen.
        assumeTrue("Smoke test expects a public build", BuildConfig.DEFAULT_CONFIG_B64.isEmpty())
        ProfileStore(context).clear()
        scenario = ActivityScenario.launch(MainActivity::class.java)
    }

    @After
    fun tearDown() {
        scenario?.close()
        scenario = null
        ProfileStore(context).clear()
    }

    @Test
    fun startsOnWelcomeScreen() {
        waitForTag(Tags.WELCOME_SCREEN)

        compose.onNodeWithText("Turbo VPN").assertIsDisplayed()
        compose.onNodeWithText("Welcome to Turbo VPN").assertIsDisplayed()
        compose.onNodeWithText("Connect to your server in a few seconds.").assertIsDisplayed()
        compose.onNodeWithText("Scan QR code").assertIsDisplayed()
        compose.onNodeWithText("Paste access link").assertIsDisplayed()
        compose.onNodeWithText("Sign in with username").assertIsDisplayed()
        compose.onNodeWithText("No code or link yet? Ask the person who runs your VPN server.").assertIsDisplayed()

        // The server settings button only exists on the home screen.
        assertEquals(0, compose.onAllNodesWithTag(Tags.SETTINGS_BUTTON).fetchSemanticsNodes().size)
    }

    @Test
    fun signInWithEmptyFieldsShowsErrors() {
        openSignIn()

        compose.onNodeWithTag(Tags.SIGN_IN_SUBMIT).performScrollTo().performClick()

        waitForText("Enter the server address")
        compose.onNodeWithText("Enter the server address").assertIsDisplayed()
        compose.onNodeWithText("Enter your username").assertIsDisplayed()
        compose.onNodeWithText("Enter your password").assertIsDisplayed()
        // Still on the sign-in screen, nothing saved.
        compose.onNodeWithTag(Tags.SIGN_IN_SCREEN).assertIsDisplayed()
        assertNull(ProfileStore(context).load())
    }

    @Test
    fun backFromSignInReturnsToWelcome() {
        openSignIn()

        compose.onNodeWithTag(Tags.SIGN_IN_BACK).performClick()

        waitForTag(Tags.WELCOME_SCREEN)
        compose.onNodeWithText("Scan QR code").assertIsDisplayed()
    }

    @Test
    fun signInReachesHomeAndRemoveReturnsToWelcome() {
        signInAs(host = HOST, username = "tester", password = "pw-1234")

        // Home: status chip, power button, and the server card showing the host.
        waitForTag(Tags.HOME_SCREEN)
        compose.onNodeWithText("Not protected").assertIsDisplayed()
        compose.onNodeWithTag(Tags.POWER_BUTTON).assertIsDisplayed()
        compose.onNodeWithText("Tap to connect").assertIsDisplayed()
        compose.onNodeWithText(HOST).assertIsDisplayed()
        compose.onNodeWithTag(Tags.SETTINGS_BUTTON).assertIsDisplayed()

        // The profile was stored (host, user) and the config was resolved by the Rust parser.
        val saved = ProfileStore(context).load()
        assertNotNull("profile was not saved", saved)
        assertEquals(HOST, saved!!.host)
        assertEquals(443, saved.port)
        assertEquals("tester", saved.username)

        // Settings -> Remove this server -> back on the welcome screen with nothing stored.
        compose.onNodeWithTag(Tags.SETTINGS_BUTTON).performClick()
        waitForTag(Tags.REMOVE_SERVER)
        compose.onNodeWithTag(Tags.REMOVE_SERVER).performScrollTo().performClick()

        waitForTag(Tags.WELCOME_SCREEN)
        compose.onNodeWithText("Scan QR code").assertIsDisplayed()
        compose.onNodeWithText("Sign in with username").assertIsDisplayed()
        assertEquals(0, compose.onAllNodesWithTag(Tags.SETTINGS_BUTTON).fetchSemanticsNodes().size)
        assertNull("profile should be gone", ProfileStore(context).load())
    }

    // ---------------------------------------------------------------- helpers

    private fun openSignIn() {
        waitForTag(Tags.WELCOME_SCREEN)
        compose.onNodeWithTag(Tags.WELCOME_SIGN_IN).performClick()
        waitForTag(Tags.SIGN_IN_SCREEN)
    }

    private fun signInAs(host: String, username: String, password: String) {
        openSignIn()
        compose.onNodeWithTag(Tags.SIGN_IN_HOST).performTextInput(host)
        compose.onNodeWithTag(Tags.SIGN_IN_USERNAME).performTextInput(username)
        compose.onNodeWithTag(Tags.SIGN_IN_PASSWORD).performTextInput(password)
        compose.onNodeWithTag(Tags.SIGN_IN_SUBMIT).performScrollTo().performClick()
    }

    private fun waitForTag(tag: String) {
        compose.waitUntil(TIMEOUT_MS) {
            compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired = false).isNotEmpty()
        }
    }

    private fun waitForText(text: String) {
        compose.waitUntil(TIMEOUT_MS) {
            compose.onAllNodesWithText(text).fetchSemanticsNodes(atLeastOneRootRequired = false).isNotEmpty()
        }
    }

    private companion object {
        const val HOST = "vpn.smoke-test.example"
        const val TIMEOUT_MS = 30_000L
    }
}
