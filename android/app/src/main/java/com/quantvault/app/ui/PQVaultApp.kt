package com.quantvault.app.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.quantvault.app.ui.components.BottomNavBar
import com.quantvault.app.ui.screens.auth.LoginScreen

sealed class Screen(val route: String) {
    object Login : Screen("login")
    object Vault : Screen("vault")
    object Authenticator : Screen("authenticator")
    object Sync : Screen("sync")
    object Settings : Screen("settings")
    object Generator : Screen("generator")
    object Passkey : Screen("passkey")
    object AddEntry : Screen("add_entry")
}

@Composable
fun PQVaultApp() {
    val navController = rememberNavController()
    var isLoggedIn by remember { mutableStateOf(false) }

    if (!isLoggedIn) {
        LoginScreen(
            onLoginSuccess = { isLoggedIn = true }
        )
    } else {
        Scaffold(
            bottomBar = {
                BottomNavBar(navController = navController)
            }
        ) { paddingValues ->
            Box(modifier = Modifier.padding(paddingValues)) {
                NavHost(
                    navController = navController,
                    startDestination = Screen.Vault.route
                ) {
                    composable(Screen.Vault.route) {
                        com.quantvault.app.ui.screens.vault.VaultScreen()
                    }
                    composable(Screen.Authenticator.route) {
                        com.quantvault.app.ui.screens.authenticator.AuthenticatorScreen()
                    }
                    composable(Screen.Sync.route) {
                        com.quantvault.app.ui.screens.sync.SyncScreen()
                    }
                    composable(Screen.Settings.route) {
                        com.quantvault.app.ui.screens.settings.SettingsScreen()
                    }
                }
            }
        }
    }
}