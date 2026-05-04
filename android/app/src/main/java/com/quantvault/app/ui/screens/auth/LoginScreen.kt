package com.quantvault.app.ui.screens.auth

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.quantvault.app.ui.components.GlassCard
import com.quantvault.app.ui.components.GoogleSignInButton
import com.quantvault.app.ui.theme.AccentBlue

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun LoginScreen(
    onLoginSuccess: () -> Unit,
    viewModel: AuthViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()
    var pin by remember { mutableStateOf("") }
    var pinVisible by remember { mutableStateOf(false) }
    var showPinSetup by remember { mutableStateOf(false) }
    var newPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var enableBiometric by remember { mutableStateOf(false) }

    LaunchedEffect(state.isVaultUnlocked) {
        if (state.isVaultUnlocked) {
            onLoginSuccess()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF0D1117),
                        Color(0xFF1A1F2E),
                        Color(0xFF0D1117)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = Icons.Default.Lock,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = AccentBlue
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "PQ Vault",
                style = MaterialTheme.typography.headlineLarge,
                color = Color.White
            )

            Text(
                text = "Post-Quantum Security",
                style = MaterialTheme.typography.bodyMedium,
                color = Color.White.copy(alpha = 0.6f)
            )

            Spacer(modifier = Modifier.height(48.dp))

            when {
                state.needsDualKey -> {
                    GlassCard {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "Two-Factor Authentication",
                                style = MaterialTheme.typography.titleMedium,
                                color = Color.White
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            Text(
                                text = "Enter your PIN to unlock the vault",
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.White.copy(alpha = 0.7f),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            OutlinedTextField(
                                value = pin,
                                onValueChange = { if (it.length <= 8) pin = it },
                                label = { Text("PIN") },
                                visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                                trailingIcon = {
                                    IconButton(onClick = { pinVisible = !pinVisible }) {
                                        Icon(
                                            if (pinVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                            contentDescription = "Toggle visibility"
                                        )
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            Button(
                                onClick = { viewModel.unlockWithPin(pin) },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = pin.length >= 4 && !state.isLoading
                            ) {
                                if (state.isLoading) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(20.dp),
                                        color = Color.White
                                    )
                                } else {
                                    Text("Unlock Vault")
                                }
                            }

                            if (state.error != null) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = state.error!!,
                                    color = MaterialTheme.colorScheme.error,
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    }
                }

                showPinSetup -> {
                    GlassCard {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "Setup Dual-Key Security",
                                style = MaterialTheme.typography.titleMedium,
                                color = Color.White
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            Text(
                                text = "Create a local PIN that will be combined with your OAuth token to form the master key",
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.White.copy(alpha = 0.7f),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            OutlinedTextField(
                                value = newPin,
                                onValueChange = { if (it.length <= 8) newPin = it },
                                label = { Text("Create PIN (4-8 digits)") },
                                visualTransformation = PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                                modifier = Modifier.fillMaxWidth()
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            OutlinedTextField(
                                value = confirmPin,
                                onValueChange = { if (it.length <= 8) confirmPin = it },
                                label = { Text("Confirm PIN") },
                                visualTransformation = PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                                modifier = Modifier.fillMaxWidth()
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Checkbox(
                                    checked = enableBiometric,
                                    onCheckedChange = { enableBiometric = it }
                                )
                                Text(
                                    text = "Enable biometric unlock",
                                    color = Color.White.copy(alpha = 0.7f)
                                )
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            Button(
                                onClick = {
                                    if (newPin == confirmPin && newPin.length >= 4) {
                                        viewModel.setupDualKey(newPin, enableBiometric)
                                        showPinSetup = false
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = newPin == confirmPin && newPin.length >= 4 && !state.isLoading
                            ) {
                                Text("Setup Dual-Key")
                            }

                            TextButton(onClick = { showPinSetup = false }) {
                                Text("Skip")
                            }
                        }
                    }
                }

                else -> {
                    GlassCard {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            if (state.hasVault) {
                                Text(
                                    text = "Welcome Back",
                                    style = MaterialTheme.typography.titleLarge,
                                    color = Color.White
                                )
                            } else {
                                Text(
                                    text = "Create Your Vault",
                                    style = MaterialTheme.typography.titleLarge,
                                    color = Color.White
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = "Sign in with Google to access your encrypted vault",
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.White.copy(alpha = 0.7f),
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(24.dp))

                            GoogleSignInButton(
                                onClick = { viewModel.signInWithGoogle() },
                                modifier = Modifier.fillMaxWidth()
                            )

                            if (state.error != null) {
                                Spacer(modifier = Modifier.height(16.dp))
                                Text(
                                    text = state.error!!,
                                    color = MaterialTheme.colorScheme.error,
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            if (state.hasVault) {
                                TextButton(onClick = { showPinSetup = true }) {
                                    Text("Enable Dual-Key Security")
                                }
                            } else {
                                TextButton(onClick = { showPinSetup = true }) {
                                    Text("Add PIN for Extra Security")
                                }
                            }
                        }
                    }
                }
            }

            if (!state.hasVault && !state.needsDualKey && !showPinSetup) {
                Spacer(modifier = Modifier.height(24.dp))

                GlassCard {
                    Column(
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Why Dual-Key?",
                            style = MaterialTheme.typography.titleSmall,
                            color = AccentBlue
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "If your Google account is hijacked, an attacker still needs your local PIN to access the vault. Your credentials remain secure even if your OAuth provider is compromised.",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.6f)
                        )
                    }
                }
            }
        }
    }
}