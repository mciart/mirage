package com.mirage.vpn.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.mirage.vpn.BuildConfig
import com.mirage.vpn.MirageVpnService
import com.mirage.vpn.R
import com.mirage.vpn.VpnViewModel

private fun startVpn(context: Context, config: String) {
    val intent = Intent(context, MirageVpnService::class.java)
        .setAction(MirageVpnService.ACTION_CONNECT)
        .putExtra(MirageVpnService.EXTRA_CONFIG, config)
    ContextCompat.startForegroundService(context, intent)
}

private fun stopVpn(context: Context) {
    val intent = Intent(context, MirageVpnService::class.java)
        .setAction(MirageVpnService.ACTION_DISCONNECT)
    ContextCompat.startForegroundService(context, intent)
}

// Which "no server yet" screen the user picked. null = the build's default (welcome, or sign-in
// for private builds that have a built-in server).
private const val ENTRY_WELCOME = "welcome"
private const val ENTRY_SIGN_IN = "sign_in"

@Composable
fun MirageApp(vm: VpnViewModel) {
    val context = LocalContext.current
    val profile by vm.profile.collectAsStateWithLifecycle()
    val pending by vm.pendingImport.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val message by vm.statusMessage.collectAsStateWithLifecycle()
    val metrics by vm.metrics.collectAsStateWithLifecycle()
    val protocol by vm.activeProtocol.collectAsStateWithLifecycle()
    val running by vm.isRunning.collectAsStateWithLifecycle()
    val samples by vm.samples.collectAsStateWithLifecycle()
    val throughput by vm.throughput.collectAsStateWithLifecycle()

    var showEditor by rememberSaveable { mutableStateOf(false) }
    var editorSession by rememberSaveable { mutableStateOf(0) }
    var showPaste by rememberSaveable { mutableStateOf(false) }
    var entry by rememberSaveable { mutableStateOf<String?>(null) }
    val snackbar = remember { SnackbarHostState() }

    // A build with a built-in server asks only for a username and password.
    val privateBuild = BuildConfig.DEFAULT_CONFIG_B64.isNotEmpty()

    LaunchedEffect(Unit) {
        vm.messages.collect { snackbar.showSnackbar(it) }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            vm.profile.value?.let { startVpn(context, it.toml) }
        } else {
            vm.say("Android needs your permission to start the VPN.")
        }
    }

    fun prepareAndStart() {
        val p = vm.profile.value ?: return
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpn(context, p.toml)
        }
    }

    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        // Proceed regardless: the VPN works without a visible notification.
        prepareAndStart()
    }

    fun onConnectClicked() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            prepareAndStart()
        }
    }

    fun scan() {
        launchQrScanner(
            context,
            onResult = { text -> vm.importFromText(text)?.let(vm::say) },
            onUnavailable = { vm.say(SCANNER_UNAVAILABLE) },
        )
    }

    val saved = profile
    // No server yet: the welcome screen, or sign-in (the default for private builds).
    val showSignIn = entry == ENTRY_SIGN_IN || (entry != ENTRY_WELCOME && privateBuild)

    // System Back walks back from sign-in to the welcome screen (and from there to the default).
    BackHandler(enabled = saved == null && entry != null) {
        entry = if (entry == ENTRY_SIGN_IN && privateBuild) ENTRY_WELCOME else null
    }

    Scaffold(
        topBar = { TopBar(showSettings = saved != null, onSettings = { showEditor = true }) },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        val content = Modifier
            .padding(padding)
            .fillMaxSize()
        when {
            saved != null -> HomeScreen(
                status = status,
                message = message,
                metrics = metrics,
                throughput = throughput,
                samples = samples,
                protocol = protocol,
                profile = saved,
                onPower = { if (running) stopVpn(context) else onConnectClicked() },
                onServer = { showEditor = true },
                modifier = content,
            )

            showSignIn -> SignInScreen(
                privateBuild = privateBuild,
                serverHost = if (privateBuild) vm.builtInHost else "",
                showBack = entry == ENTRY_SIGN_IN,
                onBack = { entry = if (privateBuild) ENTRY_WELCOME else null },
                onUseOtherWay = { entry = ENTRY_WELCOME },
                onSubmit = { host, port, username, password ->
                    val error = if (privateBuild) {
                        vm.signIn(username, password)
                    } else {
                        vm.signInWithServer(host, port, username, password)
                    }
                    if (error == null) {
                        entry = null
                        vm.say("Signed in. Tap the button to connect.")
                    }
                    error
                },
                modifier = content,
            )

            else -> WelcomeScreen(
                privateBuild = privateBuild,
                onScan = ::scan,
                onPaste = { showPaste = true },
                onSignIn = { entry = ENTRY_SIGN_IN },
                modifier = content,
            )
        }
    }

    if (showEditor) {
        key(editorSession) {
            ServerEditorSheet(
                initial = profile,
                onDismiss = { showEditor = false },
                onSave = { savedProfile ->
                    vm.saveProfile(savedProfile)
                    showEditor = false
                    vm.say(
                        if (status == MirageVpnService.STATUS_CONNECTED) "Saved. Reconnect to use the new settings."
                        else "Server saved",
                    )
                },
                onScan = ::scan,
                onPaste = { showPaste = true },
                onRemove = {
                    if (running) stopVpn(context)
                    showEditor = false
                    entry = null
                    vm.removeProfile()
                    vm.say("Server removed")
                },
            )
        }
    }

    if (showPaste) {
        PasteImportSheet(
            onDismiss = { showPaste = false },
            onSubmit = { text ->
                val err = vm.importFromText(text)
                if (err == null) showPaste = false
                err
            },
        )
    }

    pending?.let { p ->
        ImportConfirmSheet(
            pending = p,
            replacing = profile,
            onConfirm = {
                val added = vm.confirmImport()
                // The running tunnel (if any) uses the old settings.
                if (running) stopVpn(context)
                entry = null
                // Rebuild the editor from the new profile.
                showEditor = false
                editorSession++
                if (added != null && added.needsCredentials) {
                    showEditor = true
                    vm.say("Add your username and password")
                } else {
                    vm.say("Server added. Tap the button to connect.")
                }
            },
            onDismiss = vm::dismissImport,
        )
    }
}

/** Brand mark + name on the left, and (on the home screen only) the server settings button. */
@Composable
private fun TopBar(showSettings: Boolean, onSettings: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .padding(start = 20.dp, end = 10.dp, top = 8.dp, bottom = 2.dp)
            .testTag(Tags.TOP_BAR),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
            BrandMark(size = 30.dp, corner = 9.dp, glyphSize = 17.dp)
            Text(
                "Turbo VPN",
                fontSize = 19.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = (-0.2).sp,
                modifier = Modifier.semantics { heading() },
            )
        }
        if (showSettings) {
            IconButton(
                onClick = onSettings,
                modifier = Modifier
                    .semantics { contentDescription = "Server settings" }
                    .testTag(Tags.SETTINGS_BUTTON),
            ) {
                Glyph(R.drawable.ic_tune, MaterialTheme.colorScheme.onSurfaceVariant, 22.dp)
            }
        }
    }
}
