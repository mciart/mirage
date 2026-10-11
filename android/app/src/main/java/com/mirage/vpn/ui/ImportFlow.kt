package com.mirage.vpn.ui

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.mirage.vpn.R
import com.mirage.vpn.data.AccessLink
import com.mirage.vpn.data.CodecResult
import com.mirage.vpn.data.ConfigCodec
import com.mirage.vpn.data.Profile
import org.json.JSONObject

/** A decoded, parser-validated config waiting for the user's confirmation. */
data class PendingImport(
    val name: String,
    val toml: String,
    val json: JSONObject,
    /** True when it came from a mirage:// access link (QR or pasted), false for a raw config. */
    val fromLink: Boolean = true,
) {
    val host: String get() = json.optJSONObject("server")?.optString("host", "").orEmpty()
    val port: Int get() = json.optJSONObject("server")?.optInt("port", 443) ?: 443
    val insecure: Boolean get() = json.optJSONObject("transport")?.optBoolean("insecure", false) ?: false
}

const val SCANNER_UNAVAILABLE = "Scanner isn't available. Paste the link instead."

object ImportParser {
    /** Accepts a mirage:// link (alone or inside other text) or raw client TOML. */
    fun fromText(text: String): CodecResult<PendingImport> {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return CodecResult.Err("Paste a link or a config first")

        val link = AccessLink.find(trimmed)
        var name: String? = null
        val toml: String
        if (link != null) {
            when (val d = AccessLink.decode(link)) {
                is CodecResult.Err -> return d
                is CodecResult.Ok -> {
                    name = d.value.name
                    toml = d.value.toml
                }
            }
        } else {
            toml = trimmed
        }

        val json = when (val p = ConfigCodec.parse(toml)) {
            is CodecResult.Err -> return CodecResult.Err("This isn't a valid server config. ${p.message}")
            is CodecResult.Ok -> p.value
        }
        val canonical = when (val t = ConfigCodec.toToml(json)) {
            is CodecResult.Ok -> t.value
            is CodecResult.Err -> toml
        }
        val host = json.optJSONObject("server")?.optString("host", "").orEmpty()
        return CodecResult.Ok(PendingImport(name?.takeIf { it.isNotBlank() } ?: host, canonical, json, fromLink = link != null))
    }
}

/** Opens the Google code scanner (QR only, no CAMERA permission needed). */
fun launchQrScanner(context: Context, onResult: (String) -> Unit, onUnavailable: () -> Unit) {
    try {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        GmsBarcodeScanning.getClient(context, options)
            .startScan()
            .addOnSuccessListener { barcode ->
                val raw = barcode.rawValue
                if (raw.isNullOrBlank()) onUnavailable() else onResult(raw)
            }
            .addOnFailureListener { onUnavailable() }
        // User backing out of the scanner is not an error: addOnCanceledListener is deliberately unused.
    } catch (e: Exception) {
        onUnavailable()
    }
}

/** Sheet to paste a mirage:// link or raw TOML. [onSubmit] returns an error message, or null on success. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasteImportSheet(onDismiss: () -> Unit, onSubmit: (String) -> String?) {
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val clipboard = LocalClipboardManager.current

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Paste link or config", style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = text,
                onValueChange = { text = it; error = null },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(190.dp)
                    .testTag(Tags.PASTE_FIELD),
                label = { Text("An access link (mirage://…) or a client config file") },
                placeholder = { Text("mirage://import?v=1&config=…") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                isError = error != null,
                supportingText = error?.let { msg -> { Text(msg) } },
            )
            TextButton(onClick = {
                clipboard.getText()?.text?.let { text = it; error = null }
            }) { Text("Paste from clipboard") }
            Row(Modifier.padding(bottom = 16.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f).testTag(Tags.PASTE_CANCEL),
                ) { Text("Cancel") }
                Button(
                    onClick = { error = onSubmit(text) },
                    modifier = Modifier.weight(1f).testTag(Tags.PASTE_CONTINUE),
                ) { Text("Continue") }
            }
        }
    }
}

/**
 * "Add server?" (or "Replace server?" when [replacing], the profile that would be replaced).
 * Shows what the link contains so nothing is imported blindly.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportConfirmSheet(
    pending: PendingImport,
    replacing: Profile?,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    val incoming = remember(pending) { Profile(pending.name, pending.json, pending.toml) }
    val rows = listOf(
        "Server" to "${incoming.host}:${incoming.port}",
        "Account" to incoming.username.ifBlank { "Not set" },
        "Protocol" to when (incoming.protocolLabel) {
            "Auto" -> "Auto (QUIC, then TCP)"
            "Custom order" -> incoming.protocols.joinToString(", ")
            else -> incoming.protocolLabel
        },
        "Traffic" to if (incoming.allTraffic) "All traffic" else "Private network only",
        "Disguise" to when {
            !incoming.disguised -> "Off"
            incoming.targetSni.isNotBlank() -> "As ${incoming.targetSni}"
            else -> "On"
        },
    )

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                if (replacing != null) "Replace server?" else "Add server?",
                style = MaterialTheme.typography.titleLarge,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(scheme.primaryContainer),
                    contentAlignment = Alignment.Center,
                ) { Glyph(R.drawable.ic_globe, scheme.onPrimaryContainer, 20.dp) }
                Column(Modifier.weight(1f)) {
                    Text(
                        incoming.displayName,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Medium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        if (pending.fromLink) "From an access link" else "From a config file",
                        fontSize = 13.sp,
                        color = scheme.onSurfaceVariant,
                    )
                }
            }
            Column(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(scheme.surface)
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                rows.forEach { (key, value) ->
                    Row(Modifier.fillMaxWidth()) {
                        Text(key, fontSize = 13.5.sp, color = scheme.onSurfaceVariant)
                        Text(
                            value,
                            fontSize = 13.5.sp,
                            textAlign = TextAlign.End,
                            modifier = Modifier
                                .weight(1f)
                                .padding(start = 14.dp),
                        )
                    }
                }
            }
            if (pending.insecure) {
                Text(
                    "This server skips certificate checks. Only add it if you trust whoever sent the link.",
                    fontSize = 13.sp,
                    lineHeight = 19.sp,
                    color = MaterialTheme.extraColors.warn,
                )
            }
            if (replacing != null) {
                Text(
                    "This replaces ${replacing.displayName}.",
                    fontSize = 13.sp,
                    lineHeight = 19.sp,
                    color = MaterialTheme.extraColors.warn,
                )
            }
            Row(Modifier.padding(top = 4.dp, bottom = 16.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f).testTag(Tags.CONFIRM_CANCEL),
                ) { Text("Cancel") }
                Button(
                    onClick = onConfirm,
                    modifier = Modifier.weight(1f).testTag(Tags.CONFIRM_ADD),
                ) { Text(if (replacing != null) "Replace" else "Add server") }
            }
        }
    }
}
