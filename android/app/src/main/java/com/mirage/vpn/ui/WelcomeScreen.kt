package com.mirage.vpn.ui

import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mirage.vpn.R

/**
 * First screen when no server is saved: pick how to add one.
 * [privateBuild] = the app has a built-in server, so "Sign in" only needs a username and password.
 */
@Composable
fun WelcomeScreen(
    privateBuild: Boolean,
    onScan: () -> Unit,
    onPaste: () -> Unit,
    onSignIn: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scheme = MaterialTheme.colorScheme
    Column(modifier.testTag(Tags.WELCOME_SCREEN)) {
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 36.dp, bottom = 22.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                BrandMark(size = 76.dp, corner = 24.dp, glyphSize = 40.dp)
                Text(
                    "Welcome to Turbo VPN",
                    fontSize = 27.sp,
                    lineHeight = 33.sp,
                    fontWeight = FontWeight.Medium,
                    letterSpacing = (-0.4).sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .padding(top = 8.dp)
                        .semantics { heading() },
                )
                Text(
                    "Connect to your server in a few seconds.",
                    fontSize = 14.5.sp,
                    lineHeight = 22.sp,
                    color = scheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.widthIn(max = 250.dp),
                )
            }
            OptionCard(
                icon = R.drawable.ic_qr_scan,
                title = "Scan QR code",
                description = "Point at the code you were sent",
                primary = true,
                onClick = onScan,
                modifier = Modifier.testTag(Tags.WELCOME_SCAN),
            )
            OptionCard(
                icon = R.drawable.ic_link,
                title = "Paste access link",
                description = "A link that starts with mirage://",
                primary = false,
                onClick = onPaste,
                modifier = Modifier.testTag(Tags.WELCOME_PASTE),
            )
            OptionCard(
                icon = R.drawable.ic_person,
                title = "Sign in with username",
                description = if (privateBuild) "Your username and password" else "Server address, username and password",
                primary = false,
                onClick = onSignIn,
                modifier = Modifier.testTag(Tags.WELCOME_SIGN_IN),
            )
        }
        Text(
            "No code or link yet? Ask the person who runs your VPN server.",
            fontSize = 12.5.sp,
            lineHeight = 19.sp,
            color = scheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 28.dp, vertical = 16.dp),
        )
    }
}

@Composable
private fun OptionCard(
    @DrawableRes icon: Int,
    title: String,
    description: String,
    primary: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scheme = MaterialTheme.colorScheme
    val shape = RoundedCornerShape(18.dp)
    val container = if (primary) scheme.primary else scheme.surface
    val content = if (primary) scheme.onPrimary else scheme.onSurface
    Row(
        modifier
            .fillMaxWidth()
            .clip(shape)
            .background(container)
            .then(if (primary) Modifier else Modifier.border(1.dp, scheme.outlineVariant, shape))
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 13.dp),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(if (primary) scheme.onPrimary.copy(alpha = 0.18f) else scheme.surfaceContainerHigh),
            contentAlignment = Alignment.Center,
        ) {
            Glyph(icon, if (primary) scheme.onPrimary else scheme.primary, 20.dp)
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, fontSize = 15.sp, fontWeight = FontWeight.Medium, color = content)
            Text(description, fontSize = 12.5.sp, color = content, modifier = Modifier.alpha(0.75f))
        }
        Icon(
            Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = content.copy(alpha = 0.6f),
        )
    }
}
