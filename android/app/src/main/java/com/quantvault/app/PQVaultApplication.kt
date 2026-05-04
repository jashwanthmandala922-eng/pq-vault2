package com.quantvault.app

import android.app.Application
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.google.firebase.FirebaseApp
import com.quantvault.app.security.SecurityAction
import com.quantvault.app.security.TamperDetector
import com.quantvault.app.security.determineSecurityAction
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
class PQVaultApplication : Application() {
    companion object {
        private const val TAG = "PQVaultApp"
        var nativeLibraryLoaded = false
            private set
        var securityAction = SecurityAction.ALLOW
            private set
    }

    @Inject
    lateinit var tamperDetector: TamperDetector

    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        
        // Run integrity check asynchronously
        runIntegrityCheck()
        
        // Observe app lifecycle for background/foreground
        ProcessLifecycleOwner.get().lifecycle.addObserver(AppLifecycleObserver())
        
        try {
            FirebaseApp.initializeApp(this)
            Log.i(TAG, "Firebase initialized")
        } catch (e: Exception) {
            Log.w(TAG, "Firebase init warning: ${e.message}")
        }
        
        try {
            System.loadLibrary("pqvault_core")
            nativeLibraryLoaded = true
            Log.i(TAG, "Native library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native lib not available: ${e.message}")
            nativeLibraryLoaded = false
        }
    }

    private fun runIntegrityCheck() {
        applicationScope.launch {
            try {
                val result = tamperDetector.runIntegrityCheck()
                tamperDetector.updateState(result)
                
                val action = determineSecurityAction(tamperDetector.getCurrentState())
                securityAction = action
                
                val score = tamperDetector.getSecurityScore()
                Log.i(TAG, "Security check: valid=${result.isValid}, score=$score, action=$action")
                
                // Log security warnings
                if (result.isRooted) Log.w(TAG, "Device appears rooted")
                if (result.isHooked) Log.w(TAG, "Hooks detected on device")
                if (result.isEmulator) Log.w(TAG, "Running on emulator")
                
            } catch (e: Exception) {
                Log.e(TAG, "Integrity check failed: ${e.message}")
                // Fail closed - assume compromised
                securityAction = SecurityAction.BLOCK
            }
        }
    }

    /**
     * Check if vault operations should be restricted
     */
    fun shouldRestrictVaultAccess(): Boolean {
        return securityAction == SecurityAction.RESTRICT || securityAction == SecurityAction.BLOCK
    }

    /**
     * Check if sync should be disabled
     */
    fun shouldDisableSync(): Boolean {
        return securityAction == SecurityAction.BLOCK
    }

    /**
     * Get current security score
     */
    fun getSecurityScore(): Int = tamperDetector.getSecurityScore()

    /**
     * Lifecycle observer to re-check security when app goes to background
     */
    inner class AppLifecycleObserver : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) {
            // App came to foreground - optionally re-verify
            // For now, we trust the initial check
        }

        override fun onStop(owner: LifecycleOwner) {
            // App went to background
            // Could implement re-verification on foreground for high security
        }
    }
}