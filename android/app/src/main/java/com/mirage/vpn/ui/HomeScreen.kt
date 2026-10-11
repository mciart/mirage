package com.mirage.vpn.ui

import androidx.annotation.DrawableRes
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mirage.vpn.MirageVpnService
import com.mirage.vpn.R
import com.mirage.vpn.Throughput
import com.mirage.vpn.data.Profile
import java.util.Locale

/** Number of one-second samples in the sparkline. */
private const val SAMPLES = 40

@Composable
fun HomeScreen(
    status: Int,
    message: String?,
    metrics: LongArray,
    throughput: Throughput,
    samples: List<Float>,
    protocol: String,
    profile: Profile,
    onPower: () -> Unit,
    onServer: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val m = if (metrics.size >= 5) metrics else LongArray(5)
    Column(
        modifier = modifier
            .testTag(Tags.HOME_SCREEN)
            .verticalScroll(rememberScrollState())
            .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Hero(status, message, uptimeSeconds = m[4], protocol = protocol, profile = profile, onPower = onPower)
        if (status == MirageVpnService.STATUS_CONNECTED) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    RateTile(
                        label = "Download",
                        rate = throughput.downBps,
                        total = m[1],
                        icon = R.drawable.ic_arrow_down,
                        iconTint = MaterialTheme.extraColors.ok,
                        modifier = Modifier.weight(1f),
                    )
                    RateTile(
                        label = "Upload",
                        rate = throughput.upBps,
                        total = m[0],
                        icon = R.drawable.ic_arrow_up,
                        iconTint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f),
                    )
                }
                Sparkline(samples)
            }
        }
        ServerCard(profile, onServer)
    }
}

// ---------------------------------------------------------------------------------------------
// Hero: status chip, power button inside two soft rings, state text / timer, message
// ---------------------------------------------------------------------------------------------

@Composable
private fun Hero(
    status: Int,
    message: String?,
    uptimeSeconds: Long,
    protocol: String,
    profile: Profile,
    onPower: () -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    val connected = status == MirageVpnService.STATUS_CONNECTED
    val title = when (status) {
        MirageVpnService.STATUS_CONNECTING -> "Connecting…"
        MirageVpnService.STATUS_CONNECTED -> formatUptime(uptimeSeconds)
        MirageVpnService.STATUS_ERROR -> "Couldn't connect"
        else -> "Not connected"
    }
    val host = profile.host
    val detail = when (status) {
        MirageVpnService.STATUS_CONNECTING -> message?.takeIf { it.isNotBlank() } ?: "Reaching $host"
        MirageVpnService.STATUS_CONNECTED -> {
            val proto = protocolDisplay(protocol, profile)
            "Protected" + (if (proto != null) " · $proto" else "") + " to $host"
        }
        MirageVpnService.STATUS_ERROR -> message?.takeIf { it.isNotBlank() } ?: "Check the address and your login."
        else -> "Tap to connect"
    }
    val action = if (status == MirageVpnService.STATUS_CONNECTING || connected) "Disconnect" else "Connect"

    Column(
        Modifier
            .fillMaxWidth()
            .padding(top = 18.dp, bottom = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        StatusChip(status)
        PowerRing(status, action, onPower)
        if (connected) {
            Text(
                title,
                fontSize = 34.sp,
                lineHeight = 40.sp,
                letterSpacing = 0.7.sp,
                style = TextStyle(fontFeatureSettings = "tnum"),
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag(Tags.STATE_TEXT),
            )
        } else {
            Text(
                title,
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag(Tags.STATE_TEXT),
            )
        }
        Text(
            detail,
            fontSize = 13.5.sp,
            lineHeight = 19.sp,
            color = if (status == MirageVpnService.STATUS_ERROR) scheme.error else scheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .widthIn(max = 280.dp)
                .heightIn(min = 18.dp)
                .testTag(Tags.STATE_MESSAGE),
        )
    }
}

/** "QUIC" / "TCP" for the protocol in use, or null when it isn't known yet. */
private fun protocolDisplay(active: String, profile: Profile): String? =
    when (active.trim().uppercase(Locale.ROOT)) {
        "UDP", "QUIC" -> "QUIC"
        "TCP" -> "TCP"
        // Not reported yet: only name it when the config allows exactly one protocol.
        else -> profile.protocolLabel.takeIf { it == "QUIC" || it == "TCP" }
    }

@Composable
private fun StatusChip(status: Int) {
    val scheme = MaterialTheme.colorScheme
    val extra = MaterialTheme.extraColors
    val (bg, fg) = when (status) {
        MirageVpnService.STATUS_CONNECTED -> extra.okSoft to extra.onOkSoft
        MirageVpnService.STATUS_CONNECTING -> scheme.primaryContainer to scheme.onPrimaryContainer
        MirageVpnService.STATUS_ERROR -> scheme.errorContainer to scheme.onErrorContainer
        else -> scheme.surfaceContainerHigh to scheme.onSurfaceVariant
    }
    val container by animateColorAsState(bg, tween(300), label = "chipBg")
    val content by animateColorAsState(fg, tween(300), label = "chipFg")
    val text = when (status) {
        MirageVpnService.STATUS_CONNECTING -> "Connecting"
        MirageVpnService.STATUS_CONNECTED -> "Protected"
        else -> "Not protected"
    }
    val dotAlpha = if (status == MirageVpnService.STATUS_CONNECTING) {
        val blink = rememberInfiniteTransition(label = "blink")
        val a by blink.animateFloat(
            initialValue = 1f,
            targetValue = 0.25f,
            animationSpec = infiniteRepeatable(tween(500, easing = FastOutSlowInEasing), RepeatMode.Reverse),
            label = "blinkAlpha",
        )
        a
    } else {
        1f
    }
    Row(
        Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(container)
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .testTag(Tags.STATUS_CHIP),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(7.dp)
                .alpha(dotAlpha)
                .clip(CircleShape)
                .background(content),
        )
        Text(text, fontSize = 12.5.sp, fontWeight = FontWeight.Medium, color = content)
    }
}

@Composable
private fun PowerRing(status: Int, action: String, onPower: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    val extra = MaterialTheme.extraColors
    val connected = status == MirageVpnService.STATUS_CONNECTED
    val busy = status == MirageVpnService.STATUS_CONNECTING

    val outer by animateColorAsState(
        if (connected) extra.ok.copy(alpha = 0.09f) else scheme.surfaceContainerHigh.copy(alpha = 0.55f),
        tween(450),
        label = "ringOuter",
    )
    val inner by animateColorAsState(
        if (connected) extra.ok.copy(alpha = 0.17f) else scheme.surfaceContainerHigh,
        tween(450),
        label = "ringInner",
    )
    val buttonBg by animateColorAsState(
        when (status) {
            MirageVpnService.STATUS_CONNECTED -> extra.ok
            MirageVpnService.STATUS_ERROR -> scheme.errorContainer
            else -> scheme.surfaceContainerHigh
        },
        tween(300),
        label = "powerBg",
    )
    val buttonFg by animateColorAsState(
        when (status) {
            MirageVpnService.STATUS_CONNECTED -> scheme.surface
            MirageVpnService.STATUS_ERROR -> scheme.onErrorContainer
            else -> scheme.onSurfaceVariant
        },
        tween(300),
        label = "powerFg",
    )

    Box(
        Modifier
            .size(204.dp)
            .clip(CircleShape)
            .background(outer),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            Modifier
                .size(168.dp)
                .clip(CircleShape)
                .background(inner),
            contentAlignment = Alignment.Center,
        ) {
            Box(Modifier.size(148.dp), contentAlignment = Alignment.Center) {
                if (busy) Spinner(scheme.primary)
                Box(
                    Modifier
                        .size(132.dp)
                        .clip(CircleShape)
                        .background(buttonBg)
                        .clickable(onClickLabel = action, role = Role.Button, onClick = onPower)
                        .semantics { contentDescription = action }
                        .testTag(Tags.POWER_BUTTON),
                    contentAlignment = Alignment.Center,
                ) {
                    Glyph(R.drawable.ic_power, buttonFg, 46.dp)
                }
            }
        }
    }
}

/** A quarter-circle arc turning around the power button while connecting. */
@Composable
private fun Spinner(color: Color) {
    val spin = rememberInfiniteTransition(label = "spin")
    val angle by spin.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1000, easing = LinearEasing), RepeatMode.Restart),
        label = "angle",
    )
    Canvas(Modifier.size(148.dp)) {
        val w = 2.dp.toPx()
        drawArc(
            color = color,
            startAngle = angle - 135f,
            sweepAngle = 90f,
            useCenter = false,
            topLeft = Offset(w / 2, w / 2),
            size = Size(size.width - w, size.height - w),
            style = Stroke(width = w, cap = StrokeCap.Round),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Live numbers
// ---------------------------------------------------------------------------------------------

@Composable
private fun RateTile(
    label: String,
    rate: Long,
    total: Long,
    @DrawableRes icon: Int,
    iconTint: Color,
    modifier: Modifier = Modifier,
) {
    val scheme = MaterialTheme.colorScheme
    val tabular = TextStyle(fontFeatureSettings = "tnum")
    Row(
        modifier
            .clip(RoundedCornerShape(16.dp))
            .background(scheme.surfaceContainerHigh)
            .padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(32.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(scheme.surface),
            contentAlignment = Alignment.Center,
        ) { Glyph(icon, iconTint, 16.dp) }
        Column(Modifier.weight(1f)) {
            Text(label, fontSize = 11.5.sp, color = scheme.onSurfaceVariant)
            Text(
                "${formatBytes(rate)}/s",
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                style = tabular,
                maxLines = 1,
                overflow = TextOverflow.Clip,
            )
            Text(
                "${formatBytes(total)} total",
                fontSize = 11.5.sp,
                color = scheme.onSurfaceVariant,
                style = tabular,
                maxLines = 1,
                overflow = TextOverflow.Clip,
            )
        }
    }
}

/** Throughput over the last 40 one-second samples. */
@Composable
private fun Sparkline(samples: List<Float>) {
    val color = MaterialTheme.colorScheme.primary
    val padded = List((SAMPLES - samples.size).coerceAtLeast(0)) { 0f } + samples.takeLast(SAMPLES)
    Canvas(
        Modifier
            .fillMaxWidth()
            .height(40.dp)
            .semantics { contentDescription = "Throughput over the last 40 seconds" },
    ) {
        val w = size.width
        val h = size.height
        val max = padded.maxOrNull()?.coerceAtLeast(1f) ?: 1f
        val step = w / (padded.size - 1)
        val line = Path()
        padded.forEachIndexed { i, v ->
            val x = i * step
            val y = h - 3.dp.toPx() - v / max * (h - 8.dp.toPx())
            if (i == 0) line.moveTo(x, y) else line.lineTo(x, y)
        }
        val fill = Path().apply {
            addPath(line)
            lineTo(w, h)
            lineTo(0f, h)
            close()
        }
        drawPath(fill, color.copy(alpha = 0.15f))
        drawPath(line, color, style = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round))
        val last = padded.last()
        drawCircle(color, 2.6.dp.toPx(), Offset(w, h - 3.dp.toPx() - last / max * (h - 8.dp.toPx())))
    }
}

// ---------------------------------------------------------------------------------------------
// Server card
// ---------------------------------------------------------------------------------------------

@Composable
private fun ServerCard(profile: Profile, onClick: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(scheme.surfaceContainerHigh)
            .clickable(onClickLabel = "Edit server", role = Role.Button, onClick = onClick)
            .padding(14.dp)
            .testTag(Tags.SERVER_CARD),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(scheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                profile.avatarLetter,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = scheme.onPrimaryContainer,
            )
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                profile.displayName,
                fontSize = 15.sp,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                profile.summary,
                fontSize = 12.5.sp,
                color = scheme.onSurfaceVariant,
            )
        }
        Icon(
            Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = scheme.onSurfaceVariant,
        )
    }
}

internal fun formatUptime(seconds: Long): String {
    val s = seconds.coerceAtLeast(0)
    return String.format(Locale.US, "%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
}

internal fun formatBytes(bytes: Long): String {
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.coerceAtLeast(0).toDouble()
    var i = 0
    while (value >= 1024 && i < units.size - 1) {
        value /= 1024
        i++
    }
    return if (i == 0) "${value.toLong()} B" else String.format(Locale.US, "%.1f %s", value, units[i])
}
