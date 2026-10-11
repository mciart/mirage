package com.mirage.vpn

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.mirage.vpn.ui.MirageApp
import com.mirage.vpn.ui.MirageTheme

class MainActivity : ComponentActivity() {
    private val vm: VpnViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) handleIntent(intent)
        // singleTop: links opened while the app is running arrive here.
        addOnNewIntentListener { handleIntent(it) }
        setContent {
            MirageTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    MirageApp(vm)
                }
            }
        }
    }

    /** mirage://import?... deep link -> confirm sheet (never imports silently). */
    private fun handleIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW || !"mirage".equals(data.scheme, ignoreCase = true)) return
        intent.data = null // handle once
        vm.importFromText(data.toString())?.let(vm::say)
    }
}
