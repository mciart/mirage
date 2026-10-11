package com.mirage.vpn.ui

import android.content.Intent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateMap
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mirage.vpn.data.AccessLink
import com.mirage.vpn.data.CodecResult
import com.mirage.vpn.data.ConfigCodec
import com.mirage.vpn.data.Profile
import kotlinx.coroutines.launch
import org.json.JSONObject

/** Minimal valid config whose parse result supplies the Rust defaults for a new server. */
private const val TEMPLATE_TOML = """
[server]
host = "placeholder.invalid"

[authentication]
username = "placeholder"
password = "placeholder"

[log]
level = "info"
"""

private fun newServerTemplate(): JSONObject =
    when (val r = ConfigCodec.parse(TEMPLATE_TOML)) {
        is CodecResult.Ok -> r.value
        is CodecResult.Err -> JSONObject() // form defaults mirror the Rust defaults; Save reports any native error
    }

private val PROTOCOL_HINTS = mapOf(
    "auto" to "Tries QUIC first, falls back to TCP if it's blocked.",
    "udp" to "Fastest. Some networks block it.",
    "tcp" to "Works almost everywhere. A bit slower.",
    "keep" to "Using the protocol order from the imported config. Pick one to replace it.",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerEditorSheet(
    initial: Profile?,
    onDismiss: () -> Unit,
    onSave: (Profile) -> Unit,
    onScan: () -> Unit,
    onPaste: () -> Unit,
    onRemove: (() -> Unit)? = null,
) {
    // `base` is the config JSON being edited; the form writes into copies of it, so unknown keys
    // from the stored profile always survive.
    val base = remember { initial?.let { JSONObject(it.configJson.toString()) } ?: newServerTemplate() }
    val form = remember {
        ServerForm().also {
            it.loadFrom(base)
            if (initial == null) it.applyNewServerDefaults()
        }
    }
    var saveError by remember { mutableStateOf<String?>(null) }
    var advancedOpen by remember { mutableStateOf(false) }
    val openSections = remember { mutableStateMapOf<String, Boolean>() }
    val scroll = rememberScrollState()
    val scope = rememberCoroutineScope()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    fun trySave() {
        saveError = null
        if (!form.validate()) {
            val sections = form.sectionsWithErrors()
            if (sections.isNotEmpty()) {
                advancedOpen = true
                sections.forEach { openSections[it] = true }
            }
            scope.launch { scroll.animateScrollTo(0) }
            return
        }
        when (val r = form.buildProfile(base, initial)) {
            // The real Rust parser rejected it: show its message inline.
            is CodecResult.Err -> saveError = r.message
            is CodecResult.Ok -> onSave(r.value)
        }
    }

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(Modifier.fillMaxWidth().imePadding()) {
            // Header
            Row(
                Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Server", style = MaterialTheme.typography.titleLarge)
                var menu by remember { mutableStateOf(false) }
                Box {
                    TextButton(onClick = { menu = true }, modifier = Modifier.semantics { contentDescription = "Import a server" }) {
                        Text("Import")
                    }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        DropdownMenuItem(text = { Text("Scan QR code") }, onClick = { menu = false; onScan() })
                        DropdownMenuItem(text = { Text("Paste link or config") }, onClick = { menu = false; onPaste() })
                    }
                }
            }

            // Body
            Column(
                Modifier
                    .weight(1f, fill = false)
                    .testTag(Tags.EDITOR_BODY)
                    .verticalScroll(scroll)
                    .padding(horizontal = 20.dp, vertical = 6.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                BasicsGroup(form)
                ConnectionGroup(form)
                AdvancedGroup(
                    form = form,
                    base = base,
                    shareName = initial?.name?.takeIf { it.isNotBlank() } ?: form.host.trim(),
                    advancedOpen = advancedOpen,
                    onAdvancedToggle = { advancedOpen = !advancedOpen },
                    openSections = openSections,
                )
                // Only when a server is saved: forget it (and its password) and go back to the welcome screen.
                if (initial != null && onRemove != null) {
                    TextButton(
                        onClick = onRemove,
                        colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                        modifier = Modifier
                            .align(Alignment.CenterHorizontally)
                            .padding(bottom = 8.dp)
                            .testTag(Tags.REMOVE_SERVER),
                    ) { Text("Remove this server") }
                }
            }

            // Footer
            saveError?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                )
            }
            HorizontalDivider()
            Row(
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 20.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f).testTag(Tags.EDITOR_CANCEL),
                ) { Text("Cancel") }
                Button(
                    onClick = ::trySave,
                    modifier = Modifier.weight(1f).testTag(Tags.EDITOR_SAVE),
                ) { Text("Save") }
            }
        }
    }
}

@Composable
private fun BasicsGroup(form: ServerForm) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Field(
                "Server address", form.host, { form.host = it }, "host", form.errors,
                modifier = Modifier.weight(1f), placeholder = "vpn.example.com", keyboard = KeyboardType.Uri,
            )
            Field(
                "Port", form.port, { form.port = it }, "port", form.errors,
                modifier = Modifier.width(104.dp), placeholder = "443", keyboard = KeyboardType.Number,
            )
        }
        Field("Username", form.username, { form.username = it }, "username", form.errors, placeholder = "Your account name")
        Field("Password", form.password, { form.password = it }, "password", form.errors, placeholder = "Your account password", secret = true)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConnectionGroup(form: ServerForm) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        GroupLabel("CONNECTION")
        val options = listOf("auto" to "Auto", "udp" to "QUIC", "tcp" to "TCP")
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            options.forEachIndexed { i, (value, label) ->
                SegmentedButton(
                    selected = form.protocol == value,
                    onClick = { form.protocol = value },
                    shape = SegmentedButtonDefaults.itemShape(index = i, count = options.size),
                ) { Text(label) }
            }
        }
        Text(
            PROTOCOL_HINTS[form.protocol].orEmpty(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SwitchRow(
            "Send all traffic through VPN",
            "Off sends only the server's private network through the tunnel.",
            form.allTraffic,
            form::setAllTraffic,
        )
    }
}

@Composable
private fun AdvancedGroup(
    form: ServerForm,
    base: JSONObject,
    shareName: String,
    advancedOpen: Boolean,
    onAdvancedToggle: () -> Unit,
    openSections: SnapshotStateMap<String, Boolean>,
) {
    val e = form.errors
    fun isOpen(id: String) = openSections[id] == true
    fun toggle(id: String) { openSections[id] = !isOpen(id) }

    Section("Advanced", advancedOpen, onAdvancedToggle, bold = true) {
        Section("Disguise", isOpen("disguise"), { toggle("disguise") }) {
            ChoiceRow(
                "Camouflage mode",
                listOf("none" to "None", "mirage" to "Mirage"),
                form.camoMode,
            ) { form.camoMode = it }
            Field(
                "Disguise as website", form.targetSni, { form.targetSni = it }, "disguise/targetSni", e,
                placeholder = "www.microsoft.com", hint = "Target SNI. Must match the server's setting.",
            )
            Field(
                "Short IDs", form.shortIds, { form.shortIds = it }, "disguise/shortIds", e,
                multiline = true, mono = true, hint = "Hex, one per line. Must match the server.",
            )
            Field("JLS password", form.jlsPassword, { form.jlsPassword = it }, "disguise/jlsPassword", e, secret = true)
            Field("JLS IV", form.jlsIv, { form.jlsIv = it }, "disguise/jlsIv", e, secret = true)
            Field("Inner key", form.innerKey, { form.innerKey = it }, "disguise/innerKey", e, secret = true)
        }

        Section("Transport", isOpen("transport"), { toggle("transport") }) {
            Field(
                "Parallel connections", form.parallel, { form.parallel = it }, "transport/parallel", e,
                keyboard = KeyboardType.Number, hint = "1–4. More connections add bandwidth but use more resources.",
            )
            SwitchRow("Dual stack", "Use IPv4 and IPv6 connections together.", form.dualStack) { form.dualStack = it }
            Field(
                "Custom SNI", form.customSni, { form.customSni = it }, "transport/customSni", e,
                placeholder = "www.example.com", hint = "Name used for the TLS/QUIC handshake instead of the server address.",
            )
            SwitchRow(
                "Skip certificate check",
                "Only for testing with a self-signed server.",
                form.insecure,
            ) { form.insecure = it }
            if (form.insecure) {
                Text(
                    "Warning: the server's identity isn't verified, so anyone on the network could impersonate it.",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            SwitchRow("TCP no-delay", "Send small TCP packets immediately.", form.tcpNodelay) { form.tcpNodelay = it }
            Field(
                "Port hopping interval (seconds)", form.hopping, { form.hopping = it }, "transport/hopping", e,
                keyboard = KeyboardType.Number, hint = "0 turns it off. With QUIC, switches the UDP port this often.",
            )
        }

        Section("Connection", isOpen("connection"), { toggle("connection") }) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("MTU", form.mtu, { form.mtu = it }, "connection/mtu", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
                Field("Outer MTU", form.outerMtu, { form.outerMtu = it }, "connection/outerMtu", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("Timeout (s)", form.timeout, { form.timeout = it }, "connection/timeout", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
                Field("Retry (s)", form.retry, { form.retry = it }, "connection/retry", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
            }
            Field("Keep-alive (s)", form.keepAlive, { form.keepAlive = it }, "connection/keepAlive", e, keyboard = KeyboardType.Number)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("Send buffer (bytes)", form.sendBuf, { form.sendBuf = it }, "connection/sendBuf", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
                Field("Receive buffer (bytes)", form.recvBuf, { form.recvBuf = it }, "connection/recvBuf", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
            }
            SwitchRow("Reuse socket", "Share one local socket across connections.", form.reuseSocket) { form.reuseSocket = it }
            SwitchRow("Tunnel TCP no-delay", "TCP no-delay for the tunnel connection itself.", form.connNodelay) { form.connNodelay = it }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("Max lifetime (s)", form.maxLifetime, { form.maxLifetime = it }, "connection/maxLifetime", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
                Field("Lifetime jitter (s)", form.lifetimeJitter, { form.lifetimeJitter = it }, "connection/lifetimeJitter", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
            }
            Text(
                "Connections older than the max lifetime are silently replaced. 0 turns it off.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            ChoiceRow(
                "Mux mode",
                listOf("round_robin" to "Round robin", "active_standby" to "Active / standby"),
                form.muxMode,
            ) { form.muxMode = it }
        }

        Section("Obfuscation", isOpen("obfuscation"), { toggle("obfuscation") }) {
            SwitchRow("Traffic obfuscation", "Adds padding and timing noise to hide traffic patterns.", form.obfEnabled) { form.obfEnabled = it }
            Field(
                "Padding probability", form.padProb, { form.padProb = it }, "obfuscation/padProb", e,
                keyboard = KeyboardType.Decimal, hint = "0–1. Chance of sending a random padding packet.",
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("Padding min (bytes)", form.padMin, { form.padMin = it }, "obfuscation/padMin", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
                Field("Padding max (bytes)", form.padMax, { form.padMax = it }, "obfuscation/padMax", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Field("Jitter min (ms)", form.jitterMin, { form.jitterMin = it }, "obfuscation/jitterMin", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
                Field("Jitter max (ms)", form.jitterMax, { form.jitterMax = it }, "obfuscation/jitterMax", e, Modifier.weight(1f), keyboard = KeyboardType.Number)
            }
            SwitchRow("TLS record padding", "Pad writes to TLS record size. Uses more bandwidth.", form.tlsPadding) { form.tlsPadding = it }
            SwitchRow("Inner encryption", "Encrypt data again inside TLS. Needs the inner key (Disguise).", form.innerEncryption) { form.innerEncryption = it }
        }

        Section("Network", isOpen("network"), { toggle("network") }) {
            Field(
                "Routes", form.routes, { form.routes = it }, "network/routes", e,
                multiline = true, mono = true,
                hint = "One per line, like 10.0.0.0/8. \"Send all traffic\" edits this list.",
            )
            Field(
                "Excluded routes", form.excluded, { form.excluded = it }, "network/excluded", e,
                multiline = true, mono = true, hint = "One per line. These bypass the VPN.",
            )
            Field(
                "DNS servers", form.dns, { form.dns = it }, "network/dns", e,
                multiline = true, mono = true, hint = "One IP address per line (or separated by commas).",
            )
            Field(
                "Static client IP", form.staticIp, { form.staticIp = it }, "network/staticIp", e,
                placeholder = "10.11.12.13", hint = "Optional. The connection is refused if the server already gave it out.",
            )
            Field(
                "Static client IP (IPv6)", form.staticIpV6, { form.staticIpV6 = it }, "network/staticIpV6", e,
                placeholder = "fd00::fd00", hint = "Optional.",
            )
        }

        Section("Certificates", isOpen("certs"), { toggle("certs") }) {
            Field(
                "Trusted certificates", form.certs, { form.certs = it }, "certs/pem", e,
                multiline = true, mono = true, placeholder = "-----BEGIN CERTIFICATE-----",
                hint = "Paste PEM certificates for a self-signed server or private CA.",
            )
        }

        Section("Logging", isOpen("logging"), { toggle("logging") }) {
            ChoiceRow(
                "Log level",
                listOf("trace", "debug", "info", "warn", "error").map { it to it },
                form.logLevel,
            ) { form.logLevel = it }
        }

        Section("Config file", isOpen("file"), { toggle("file") }) {
            ConfigFileSection(form, base, shareName)
        }
    }
}

@Composable
private fun ConfigFileSection(form: ServerForm, base: JSONObject, name: String) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var reveal by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }

    when (val result = form.previewToml(base)) {
        is CodecResult.Err -> Text(
            "Can't show the config yet: ${result.message}",
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
        is CodecResult.Ok -> {
            val toml = result.value
            val shown = if (reveal) toml else SECRET_LINE.replace(toml, "\$1\"••••••••\"")
            Text(
                shown,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.5.sp,
                lineHeight = 18.sp,
                softWrap = false,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.surface)
                    .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
                    .heightIn(max = 260.dp)
                    .verticalScroll(rememberScrollState())
                    .horizontalScroll(rememberScrollState())
                    .padding(12.dp),
            )
            TextButton(onClick = { reveal = !reveal }) { Text(if (reveal) "Hide secrets" else "Show secrets") }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { clipboard.setText(AnnotatedString(toml)); note = "Config copied" },
                    modifier = Modifier.weight(1f),
                ) { Text("Copy config") }
                OutlinedButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(AccessLink.encode(name, toml)))
                        note = "Link copied"
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Copy link") }
            }
            Button(
                onClick = {
                    val link = AccessLink.encode(name, toml)
                    val send = Intent(Intent.ACTION_SEND)
                        .setType("text/plain")
                        .putExtra(Intent.EXTRA_TEXT, link)
                    context.startActivity(Intent.createChooser(send, "Share access link"))
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Share access link") }
            Text(
                note ?: "The access link contains your password. Only share it with people you trust.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private val SECRET_LINE = Regex("(?m)^(\\s*(?:password|jls_password|jls_iv|inner_key)\\s*=\\s*).*$")

// ---------------------------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------------------------

@Composable
private fun GroupLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
    )
}

@Composable
private fun Section(
    title: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    bold: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider()
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .clickable(onClickLabel = if (expanded) "Collapse $title" else "Expand $title", role = Role.Button, onClick = onToggle)
                .semantics { stateDescription = if (expanded) "Expanded" else "Collapsed" }
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(title, style = if (bold) MaterialTheme.typography.titleMedium else MaterialTheme.typography.bodyLarge)
            Icon(
                Icons.Default.KeyboardArrowDown,
                contentDescription = null,
                modifier = Modifier.rotate(if (expanded) 180f else 0f),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        AnimatedVisibility(visible = expanded) {
            Column(
                Modifier.padding(bottom = 10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                content = content,
            )
        }
    }
}

@Composable
private fun Field(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    errorKey: String,
    errors: SnapshotStateMap<String, String>,
    modifier: Modifier = Modifier.fillMaxWidth(),
    placeholder: String? = null,
    hint: String? = null,
    keyboard: KeyboardType = KeyboardType.Text,
    secret: Boolean = false,
    multiline: Boolean = false,
    mono: Boolean = false,
) {
    var reveal by remember { mutableStateOf(false) }
    val error = errors[errorKey]
    val supporting: (@Composable () -> Unit)? = (error ?: hint)?.let { text -> { Text(text) } }
    val placeholderSlot: (@Composable () -> Unit)? = placeholder?.let { text -> { Text(text) } }
    val trailing: (@Composable () -> Unit)? = if (secret) {
        { RevealToggle(label, reveal) { reveal = !reveal } }
    } else null

    OutlinedTextField(
        value = value,
        onValueChange = {
            onChange(it)
            if (error != null) errors.remove(errorKey)
        },
        modifier = modifier,
        label = { Text(label) },
        placeholder = placeholderSlot,
        supportingText = supporting,
        trailingIcon = trailing,
        isError = error != null,
        singleLine = !multiline,
        minLines = if (multiline) 2 else 1,
        maxLines = if (multiline) 8 else 1,
        textStyle = if (mono) {
            MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
        } else {
            MaterialTheme.typography.bodyLarge
        },
        visualTransformation = if (secret && !reveal) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (secret && !reveal) KeyboardType.Password else keyboard),
    )
}

@Composable
private fun SwitchRow(title: String, description: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = null)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ChoiceRow(
    label: String,
    options: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            options.forEach { (value, text) ->
                FilterChip(selected = selected == value, onClick = { onSelect(value) }, label = { Text(text) })
            }
        }
    }
}
