package com.mirage.vpn.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/*
 * Brand colours from the approved design. A fixed palette (no wallpaper-based dynamic colour) so
 * the app looks the same on every device.
 *
 * Token mapping used throughout the UI:
 *   surface                -> --surface   (screen background)
 *   surfaceContainerHigh   -> --surface-2 (tiles, cards, idle power button)
 *   surfaceContainerLow    -> --sheet     (bottom sheets)
 *   onSurfaceVariant       -> --ink-2     (secondary text)
 *   outline / outlineVariant -> --line-strong / --line
 *   primaryContainer       -> --primary-soft
 */
private val LightColors = lightColorScheme(
    primary = Color(0xFF415F91),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD6E3FF),
    onPrimaryContainer = Color(0xFF001B3E),
    secondary = Color(0xFF565F71),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD6E3FF),
    onSecondaryContainer = Color(0xFF001B3E),
    tertiary = Color(0xFF705575),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFAD8FD),
    onTertiaryContainer = Color(0xFF28132E),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF9F9FF),
    onBackground = Color(0xFF191C20),
    surface = Color(0xFFF9F9FF),
    onSurface = Color(0xFF191C20),
    surfaceVariant = Color(0xFFE0E2EC),
    onSurfaceVariant = Color(0xFF4A4D55),
    outline = Color(0xFF74777F),
    outlineVariant = Color(0xFFC4C6D0),
    inverseSurface = Color(0xFF191C20),
    inverseOnSurface = Color(0xFFF9F9FF),
    inversePrimary = Color(0xFFAAC7FF),
    surfaceTint = Color(0xFF415F91),
    scrim = Color(0xFF000000),
    surfaceDim = Color(0xFFD9D9E0),
    surfaceBright = Color(0xFFF9F9FF),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF3F3FA),
    surfaceContainer = Color(0xFFEEEEF5),
    surfaceContainerHigh = Color(0xFFEEEEF5),
    surfaceContainerHighest = Color(0xFFEEEEF5),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFAAC7FF),
    onPrimary = Color(0xFF0A305F),
    primaryContainer = Color(0xFF284777),
    onPrimaryContainer = Color(0xFFD6E3FF),
    secondary = Color(0xFFBEC6DC),
    onSecondary = Color(0xFF283141),
    secondaryContainer = Color(0xFF284777),
    onSecondaryContainer = Color(0xFFD6E3FF),
    tertiary = Color(0xFFDDBCE0),
    onTertiary = Color(0xFF3F2844),
    tertiaryContainer = Color(0xFF573E5C),
    onTertiaryContainer = Color(0xFFFAD8FD),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF111318),
    onBackground = Color(0xFFE2E2E9),
    surface = Color(0xFF111318),
    onSurface = Color(0xFFE2E2E9),
    surfaceVariant = Color(0xFF44474F),
    onSurfaceVariant = Color(0xFFC4C6D0),
    outline = Color(0xFF8E9099),
    outlineVariant = Color(0xFF3A3D44),
    inverseSurface = Color(0xFFE2E2E9),
    inverseOnSurface = Color(0xFF111318),
    inversePrimary = Color(0xFF415F91),
    surfaceTint = Color(0xFFAAC7FF),
    scrim = Color(0xFF000000),
    surfaceDim = Color(0xFF111318),
    surfaceBright = Color(0xFF37393E),
    surfaceContainerLowest = Color(0xFF0C0E13),
    surfaceContainerLow = Color(0xFF1D2024),
    // Pop-up menus sit on top of the (1D2024) sheet, so they are one step lighter.
    surfaceContainer = Color(0xFF282A2F),
    surfaceContainerHigh = Color(0xFF1D2024),
    surfaceContainerHighest = Color(0xFF1D2024),
)

/** Colours the Material scheme has no slot for: success ("ok") and warning. */
@Immutable
class ExtraColors(
    val ok: Color,
    val okSoft: Color,
    val onOkSoft: Color,
    val warn: Color,
)

private val LightExtraColors = ExtraColors(
    ok = Color(0xFF17805A),
    okSoft = Color(0xFFD2F1E3),
    onOkSoft = Color(0xFF003920),
    warn = Color(0xFF7A5900),
)

private val DarkExtraColors = ExtraColors(
    ok = Color(0xFF7FD8AC),
    okSoft = Color(0xFF0F3D2A),
    onOkSoft = Color(0xFFC8F5DD),
    warn = Color(0xFFF1C048),
)

private val LocalExtraColors = staticCompositionLocalOf { LightExtraColors }

/** `MaterialTheme.extraColors.ok` etc. */
val MaterialTheme.extraColors: ExtraColors
    @Composable
    @ReadOnlyComposable
    get() = LocalExtraColors.current

@Composable
fun MirageTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val scheme = if (dark) DarkColors else LightColors
    SystemBarsEffect(dark, scheme)
    CompositionLocalProvider(LocalExtraColors provides (if (dark) DarkExtraColors else LightExtraColors)) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

/**
 * Keeps the system bars in step with the theme while the app is open (the window theme in the
 * themes.xml files under res only covers the moment before the first frame).
 */
@Composable
private fun SystemBarsEffect(dark: Boolean, scheme: ColorScheme) {
    val view = LocalView.current
    if (view.isInEditMode) return
    val background = scheme.surface
    SideEffect {
        val window = view.context.findActivity()?.window ?: return@SideEffect
        val argb = background.toArgb()
        window.statusBarColor = argb
        val controller = WindowCompat.getInsetsController(window, view)
        controller.isAppearanceLightStatusBars = !dark
        // Dark navigation-bar icons only exist from API 27; older versions keep the system default.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            window.navigationBarColor = argb
            controller.isAppearanceLightNavigationBars = !dark
        }
    }
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
