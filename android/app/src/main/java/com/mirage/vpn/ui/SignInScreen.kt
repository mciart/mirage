package com.mirage.vpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Longest valid TCP/UDP port. */
private const val MAX_PORT = 65535
const val DEFAULT_PORT = 443

/**
 * Sign in with a username and password.
 *
 *  - Public build ([privateBuild] = false): also asks for the server address and port.
 *  - Private build: the server is built into the app; only username and password are asked,
 *    and [serverHost] (the built-in server's address) is named in the description.
 *
 * [onSubmit] gets (host, port, username, password) with host/port empty/0 for private builds, and
 * returns an error message to show under the form, or null on success.
 */
@Composable
fun SignInScreen(
    privateBuild: Boolean,
    serverHost: String,
    showBack: Boolean,
    onBack: () -> Unit,
    onUseOtherWay: () -> Unit,
    onSubmit: (host: String, port: Int, username: String, password: String) -> String?,
    modifier: Modifier = Modifier,
) {
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf(DEFAULT_PORT.toString()) }
    var username by rememberSaveable { mutableStateOf("") }
    // The password is deliberately not saved across process death.
    var password by remember { mutableStateOf("") }
    var hostError by remember { mutableStateOf<String?>(null) }
    var portError by remember { mutableStateOf<String?>(null) }
    var userError by remember { mutableStateOf<String?>(null) }
    var passError by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val focus = LocalFocusManager.current

    fun submit() {
        error = null
        var portValue = 0
        if (!privateBuild) {
            val h = host.trim()
            hostError = when {
                h.isEmpty() -> "Enter the server address"
                h.any { it.isWhitespace() } || h.contains("://") -> "Use just the address, like vpn.example.com"
                else -> null
            }
            val p = port.trim().ifEmpty { DEFAULT_PORT.toString() }
            val parsed = if (p.length <= 5 && p.all { it in '0'..'9' }) p.toInt() else 0
            if (parsed in 1..MAX_PORT) {
                portValue = parsed
                portError = null
            } else {
                portError = "1–$MAX_PORT"
            }
        }
        userError = if (username.isBlank()) "Enter your username" else null
        passError = if (password.isEmpty()) "Enter your password" else null
        if (hostError != null || portError != null || userError != null || passError != null) return
        focus.clearFocus()
        error = onSubmit(host.trim(), portValue, username.trim(), password)
    }

    Column(
        modifier
            .testTag(Tags.SIGN_IN_SCREEN)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (showBack) {
            TextButton(onClick = onBack, modifier = Modifier.testTag(Tags.SIGN_IN_BACK)) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("Back", modifier = Modifier.padding(start = 6.dp))
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                "Sign in",
                fontSize = 26.sp,
                lineHeight = 32.sp,
                modifier = Modifier.semantics { heading() },
            )
            Text(
                if (privateBuild) {
                    if (serverHost.isNotBlank()) "Enter the username and password you were given for $serverHost."
                    else "Enter the username and password you were given."
                } else {
                    "Enter the details you were given."
                },
                fontSize = 14.sp,
                lineHeight = 21.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (!privateBuild) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                FormTextField(
                    label = "Server address",
                    value = host,
                    onValueChange = { host = it; hostError = null },
                    modifier = Modifier.weight(1f).testTag(Tags.SIGN_IN_HOST),
                    error = hostError,
                    placeholder = "vpn.example.com",
                    keyboardType = KeyboardType.Uri,
                )
                FormTextField(
                    label = "Port",
                    value = port,
                    onValueChange = { port = it; portError = null },
                    modifier = Modifier.width(104.dp).testTag(Tags.SIGN_IN_PORT),
                    error = portError,
                    keyboardType = KeyboardType.Number,
                )
            }
        }
        FormTextField(
            label = "Username",
            value = username,
            onValueChange = { username = it; userError = null },
            modifier = Modifier.fillMaxWidth().testTag(Tags.SIGN_IN_USERNAME),
            error = userError,
        )
        FormTextField(
            label = "Password",
            value = password,
            onValueChange = { password = it; passError = null },
            modifier = Modifier.fillMaxWidth().testTag(Tags.SIGN_IN_PASSWORD),
            error = passError,
            imeAction = ImeAction.Done,
            onImeAction = ::submit,
            secret = true,
        )
        if (!privateBuild) {
            Text(
                "If your server uses disguise keys, sign in with its QR code or link instead. They carry the keys for you.",
                fontSize = 12.5.sp,
                lineHeight = 18.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                    .padding(horizontal = 12.dp, vertical = 10.dp),
            )
        }
        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Button(
            onClick = ::submit,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag(Tags.SIGN_IN_SUBMIT),
        ) { Text("Sign in", fontSize = 14.5.sp) }
        if (privateBuild) {
            TextButton(
                onClick = onUseOtherWay,
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .testTag(Tags.SIGN_IN_OTHER_WAY),
            ) { Text("Use a QR code or link instead") }
        }
    }
}
