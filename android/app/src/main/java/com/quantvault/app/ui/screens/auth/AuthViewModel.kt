package com.quantvault.app.ui.screens.auth

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.quantvault.app.data.auth.FirebaseAuthManager
import com.quantvault.app.data.repository.VaultRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class AuthState(
    val isLoading: Boolean = false,
    val isAuthenticated: Boolean = false,
    val needsDualKey: Boolean = false,
    val isVaultUnlocked: Boolean = false,
    val error: String? = null,
    val hasVault: Boolean = false
)

@HiltViewModel
class AuthViewModel @Inject constructor(
    private val firebaseAuthManager: FirebaseAuthManager,
    private val vaultRepository: VaultRepository
) : ViewModel() {

    private val _state = MutableStateFlow(AuthState())
    val state: StateFlow<AuthState> = _state.asStateFlow()

    init {
        checkVaultStatus()
    }

    private fun checkVaultStatus() {
        _state.value = _state.value.copy(
            hasVault = vaultRepository.hasVault(),
            isVaultUnlocked = vaultRepository.isUnlocked()
        )
    }

    fun signInWithGoogle() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            try {
                val result = firebaseAuthManager.handleSignInResult(null)
                result.fold(
                    onSuccess = { user ->
                        val token = firebaseAuthManager.getAccessToken() ?: user.idToken ?: ""
                        _state.value = _state.value.copy(
                            isAuthenticated = true,
                            isLoading = false
                        )
                        handlePostLogin(token)
                    },
                    onFailure = { e ->
                        _state.value = _state.value.copy(
                            isLoading = false,
                            error = e.message ?: "Sign in failed"
                        )
                    }
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isLoading = false,
                    error = e.message ?: "Sign in failed"
                )
            }
        }
    }

    private fun handlePostLogin(token: String) {
        if (vaultRepository.isDualKeyEnabled()) {
            _state.value = _state.value.copy(needsDualKey = true)
        } else {
            unlockVault(token)
        }
    }

    fun unlockWithPin(pin: String) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            
            val token = firebaseAuthManager.getAccessToken() ?: ""
            val result = vaultRepository.unlockWithToken(token, pin)
            
            result.fold(
                onSuccess = {
                    _state.value = _state.value.copy(
                        isVaultUnlocked = true,
                        needsDualKey = false,
                        isLoading = false
                    )
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = "Invalid PIN or vault locked"
                    )
                }
            )
        }
    }

    fun unlockWithBiometric() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            
            val token = firebaseAuthManager.getAccessToken() ?: ""
            val result = vaultRepository.unlockWithBiometric(token)
            
            result.fold(
                onSuccess = {
                    _state.value = _state.value.copy(
                        isVaultUnlocked = true,
                        needsDualKey = false,
                        isLoading = false
                    )
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = "Biometric unlock failed: ${e.message}"
                    )
                }
            )
        }
    }

    private fun unlockVault(token: String) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            
            val result = vaultRepository.unlockWithToken(token)
            
            result.fold(
                onSuccess = {
                    _state.value = _state.value.copy(
                        isVaultUnlocked = true,
                        isLoading = false
                    )
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = "Failed to unlock vault: ${e.message}"
                    )
                }
            )
        }
    }

    fun createVault(oauthToken: String, localKey: ByteArray? = null) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            
            val result = vaultRepository.createVault(oauthToken, localKey)
            
            result.fold(
                onSuccess = {
                    _state.value = _state.value.copy(
                        isVaultUnlocked = true,
                        hasVault = true,
                        isLoading = false
                    )
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = "Failed to create vault: ${e.message}"
                    )
                }
            )
        }
    }

    fun setupDualKey(pin: String, useBiometric: Boolean) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            
            val result = vaultRepository.setupDualKey(pin, useBiometric)
            
            result.fold(
                onSuccess = {
                    _state.value = _state.value.copy(isLoading = false)
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = "Failed to setup dual-key: ${e.message}"
                    )
                }
            )
        }
    }

    fun disableDualKey() {
        viewModelScope.launch {
            _state.value = _state.value.copy(isLoading = true, error = null)
            
            val result = vaultRepository.disableDualKey()
            
            result.fold(
                onSuccess = {
                    _state.value = _state.value.copy(isLoading = false)
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(
                        isLoading = false,
                        error = "Failed to disable dual-key: ${e.message}"
                    )
                }
            )
        }
    }

    fun lock() {
        vaultRepository.lock()
        _state.value = _state.value.copy(
            isVaultUnlocked = false,
            needsDualKey = false
        )
    }

    fun clearError() {
        _state.value = _state.value.copy(error = null)
    }
}