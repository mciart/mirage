package com.mirage.vpn.ui

import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.mirage.vpn.R

/** A decorative vector icon from res/drawable (tinted; the surrounding text carries the meaning). */
@Composable
fun Glyph(@DrawableRes id: Int, tint: Color, size: Dp = 20.dp, modifier: Modifier = Modifier) {
    Icon(painterResource(id), contentDescription = null, tint = tint, modifier = modifier.size(size))
}

/** The app mark: a bolt on a rounded square in the primary colour. */
@Composable
fun BrandMark(size: Dp, corner: Dp, glyphSize: Dp, modifier: Modifier = Modifier) {
    Box(
        modifier
            .size(size)
            .clip(RoundedCornerShape(corner))
            .background(MaterialTheme.colorScheme.primary),
        contentAlignment = Alignment.Center,
    ) {
        Glyph(R.drawable.ic_bolt, MaterialTheme.colorScheme.onPrimary, glyphSize)
    }
}
