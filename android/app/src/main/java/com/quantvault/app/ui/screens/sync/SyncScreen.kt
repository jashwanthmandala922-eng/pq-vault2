package com.quantvault.app.ui.screens.sync

import android.Manifest
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.quantvault.app.data.sync.SyncPeer
import com.quantvault.app.data.sync.SyncRepository
import com.quantvault.app.ui.components.GlassCard
import com.quantvault.app.ui.theme.AccentBlue
import com.quantvault.app.ui.theme.AccentGreen
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SyncState(
    val isScanning: Boolean = false,
    val isPairing: Boolean = false,
    val isVerified: Boolean = false,
    val showQR: Boolean = false,
    val showSASVerification: Boolean = false,
    val sasCode: String = "",
    val localDeviceId: String = "",
    val peers: List<SyncPeer> = emptyList(),
    val syncInProgress: Boolean = false,
    val error: String? = null
)

@HiltViewModel
class SyncViewModel @Inject constructor(
    private val syncRepository: SyncRepository
) : ViewModel() {

    private val _state = MutableStateFlow(SyncState())
    val state: StateFlow<SyncState> = _state.asStateFlow()

    init {
        _state.value = _state.value.copy(localDeviceId = syncRepository.getLocalDeviceId())
    }

    fun startScanning() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isScanning = true, error = null)
            try {
                val peers = syncRepository.discoverPeers()
                _state.value = _state.value.copy(isScanning = false, peers = peers)
            } catch (e: Exception) {
                _state.value = _state.value.copy(isScanning = false, error = e.message)
            }
        }
    }

    fun showQRCode() {
        _state.value = _state.value.copy(showQR = true)
    }

    fun hideQRCode() {
        _state.value = _state.value.copy(showQR = false)
    }

    fun initiatePairing(peer: SyncPeer) {
        _state.value = _state.value.copy(isPairing = true)
    }

    fun processQRCode(qrContent: String) {
        val success = syncRepository.startPairingScan(qrContent)
        if (success) {
            _state.value = _state.value.copy(
                showQR = false,
                isPairing = false,
                showSASVerification = true,
                sasCode = syncRepository.getSASCode() ?: ""
            )
        } else {
            _state.value = _state.value.copy(error = "Invalid QR code")
        }
    }

    fun verifySAS(enteredSAS: String): Boolean {
        val verified = syncRepository.verifySAS(enteredSAS)
        if (verified) {
            _state.value = _state.value.copy(
                showSASVerification = false,
                isVerified = true
            )
        } else {
            _state.value = _state.value.copy(error = "SAS code mismatch")
        }
        return verified
    }

    fun syncWithPeer(peer: SyncPeer) {
        if (!isVerified()) {
            _state.value = _state.value.copy(error = "Complete mutual authentication first")
            return
        }

        viewModelScope.launch {
            _state.value = _state.value.copy(syncInProgress = true)
            val result = syncRepository.initiateSyncWithPeer(peer)
            _state.value = _state.value.copy(
                syncInProgress = false,
                error = result.exceptionOrNull()?.message
            )
        }
    }

    fun resetPairing() {
        syncRepository.resetPairing()
        _state.value = _state.value.copy(
            isVerified = false,
            showSASVerification = false,
            sasCode = ""
        )
    }

    fun isVerified(): Boolean = syncRepository.isMutualAuthVerified()

    fun getQRBitmap() = syncRepository.generateQRBitmap()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(
    viewModel: SyncViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(Color(0xFF0D1117), Color(0xFF1A1F2E), Color(0xFF0D1117))
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            Text(
                text = "P2P Sync",
                style = MaterialTheme.typography.headlineMedium,
                color = Color.White,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Device: ${state.localDeviceId.take(8)}...",
                style = MaterialTheme.typography.bodySmall,
                color = Color.White.copy(alpha = 0.6f)
            )

            Spacer(modifier = Modifier.height(16.dp))

            GlassCard {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (state.isVerified) Icons.Default.CheckCircle else Icons.Default.Security,
                            contentDescription = null,
                            tint = if (state.isVerified) AccentGreen else AccentBlue,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (state.isVerified) "Verified" else "Not Verified",
                            style = MaterialTheme.typography.titleMedium,
                            color = Color.White
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = if (state.isVerified) 
                            "Secure channel established" 
                        else 
                            "Complete mutual authentication to enable sync",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White.copy(alpha = 0.6f)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (!state.isVerified) {
                GlassCard {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "Mutual Authentication",
                            style = MaterialTheme.typography.titleMedium,
                            color = Color.White
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { viewModel.showQRCode() },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
                            ) {
                                Icon(Icons.Default.QrCode, contentDescription = null)
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Show QR")
                            }

                            OutlinedButton(
                                onClick = { viewModel.startScanning() },
                                modifier = Modifier.weight(1f),
                                enabled = !state.isScanning
                            ) {
                                if (state.isScanning) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        color = Color.White
                                    )
                                } else {
                                    Icon(Icons.Default.Search, contentDescription = null)
                                }
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Scan")
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = "Scan peer's QR code to verify identity and establish encrypted connection",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.6f)
                        )
                    }
                }
            } else {
                GlassCard {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "Sync",
                            style = MaterialTheme.typography.titleMedium,
                            color = Color.White
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        if (state.peers.isEmpty()) {
                            Button(
                                onClick = { viewModel.startScanning() },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !state.isScanning
                            ) {
                                Text("Search for Devices")
                            }
                        } else {
                            LazyColumn(
                                modifier = Modifier.heightIn(max = 200.dp)
                            ) {
                                items(state.peers) { peer ->
                                    DeviceItem(
                                        peer = peer,
                                        onClick = { viewModel.syncWithPeer(peer) },
                                        isSyncing = state.syncInProgress
                                    )
                                }
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

                Spacer(modifier = Modifier.height(8.dp))

                TextButton(
                    onClick = { viewModel.resetPairing() },
                    modifier = Modifier.align(Alignment.CenterHorizontally)
                ) {
                    Text("Reset Authentication", color = Color.White.copy(alpha = 0.6f))
                }
            }
        }

        if (state.showQR) {
            QRDialog(
                qrBitmap = viewModel.getQRBitmap(),
                deviceId = state.localDeviceId,
                onDismiss = { viewModel.hideQRCode() },
                onManualInput = { code -> viewModel.processQRCode(code) }
            )
        }

        if (state.showSASVerification) {
            SASVerificationDialog(
                sasCode = state.sasCode,
                onVerify = { entered -> 
                    val success = viewModel.verifySAS(entered)
                    if (!success) {
                        viewModel.resetPairing()
                    }
                    success
                },
                onCancel = { viewModel.resetPairing() }
            )
        }
    }
}

@Composable
fun DeviceItem(
    peer: SyncPeer,
    onClick: () -> Unit,
    isSyncing: Boolean
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(Color.White.copy(alpha = 0.05f))
            .clickable(enabled = !isSyncing, onClick = onClick)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.Default.Smartphone,
            contentDescription = null,
            tint = AccentBlue
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = peer.displayName,
                style = MaterialTheme.typography.bodyMedium,
                color = Color.White
            )
            Text(
                text = peer.ipAddress,
                style = MaterialTheme.typography.bodySmall,
                color = Color.White.copy(alpha = 0.6f)
            )
        }
        if (isSyncing) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                color = AccentBlue
            )
        } else {
            Icon(
                imageVector = Icons.Default.Sync,
                contentDescription = "Sync",
                tint = AccentGreen
            )
        }
    }
}

@Composable
fun QRDialog(
    qrBitmap: android.graphics.Bitmap?,
    deviceId: String,
    onDismiss: () -> Unit,
    onManualInput: (String) -> Unit
) {
    var manualCode by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text("Show this QR to peer", color = Color.White)
        },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (qrBitmap != null) {
                    Image(
                        bitmap = qrBitmap.asImageBitmap(),
                        contentDescription = "QR Code",
                        modifier = Modifier
                            .size(200.dp)
                            .border(2.dp, AccentBlue, RoundedCornerShape(8.dp))
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Device ID: ${deviceId.take(8)}...",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.White.copy(alpha = 0.6f)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text("Or enter peer's QR data:", color = Color.White.copy(alpha = 0.7f))

                OutlinedTextField(
                    value = manualCode,
                    onValueChange = { manualCode = it },
                    label = { Text("QR Data") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }
        },
        confirmButton = {
            Button(onClick = { 
                if (manualCode.isNotBlank()) {
                    onManualInput(manualCode)
                }
            }) {
                Text("Confirm")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
        containerColor = Color(0xFF1A1F2E)
    )
}

@Composable
fun SASVerificationDialog(
    sasCode: String,
    onVerify: (String) -> Boolean,
    onCancel: () -> Unit
) {
    var enteredCode by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onCancel,
        title = {
            Text("Verify Peer Identity", color = Color.White)
        },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Compare this code with your peer:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color.White.copy(alpha = 0.7f)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Box(
                    modifier = Modifier
                        .background(
                            Color.White.copy(alpha = 0.1f),
                            RoundedCornerShape(8.dp)
                        )
                        .padding(16.dp)
                ) {
                    Text(
                        text = sasCode,
                        style = MaterialTheme.typography.headlineLarge.copy(
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 4.sp
                        ),
                        color = AccentBlue,
                        textAlign = TextAlign.Center
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Enter peer's displayed code:",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.White.copy(alpha = 0.7f)
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = enteredCode,
                    onValueChange = { if (it.length <= 6) enteredCode = it },
                    label = { Text("SAS Code") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    isError = error != null
                )

                if (error != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "If codes match, tap Confirm to establish secure channel",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.White.copy(alpha = 0.5f),
                    textAlign = TextAlign.Center
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { 
                    val success = onVerify(enteredCode)
                    if (!success) {
                        error = "Codes don't match - verification failed"
                    }
                },
                enabled = enteredCode.length == 6
            ) {
                Text("Confirm")
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        },
        containerColor = Color(0xFF1A1F2E)
    )
}