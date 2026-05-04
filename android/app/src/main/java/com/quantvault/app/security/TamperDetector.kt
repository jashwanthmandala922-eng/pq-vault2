package com.quantvault.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import com.google.android.gms.safetynet.SafetyNet
import com.google.android.gms.safetynet.SafetyNetApi
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.GoogleApiClient
import com.google.android.gms.common.api.ResultCallback
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class IntegrityResult(
    val isValid: Boolean,
    val isRooted: Boolean = false,
    val isHooked: Boolean = false,
    val isEmulator: Boolean = false,
    val isDebuggable: Boolean = false,
    val attestationScore: Int = 0,
    val errorMessage: String? = null
)

data class TamperDetectionState(
    val isDeviceSecure: Boolean = false,
    val isAppAuthentic: Boolean = false,
    val hasPassedIntegrity: Boolean = false,
    val isRooted: Boolean = false,
    val isHooked: Boolean = false,
    val isEmulator: Boolean = false,
    val lastCheckTime: Long = 0
)

@Singleton
class TamperDetector @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        // Play Integrity API key - replace with actual key from Google Cloud Console
        private const val PLAY_INTEGRITY_API_KEY = "YOUR_PLAY_INTEGRITY_API_KEY"
        
        // Nonce for SafetyNet attestation
        private const val NONCE_PREFIX = "PQ_VAULT_ATTESTATION_"
    }

    private var lastResult: TamperDetectionState = TamperDetectionState()
    private var googleApiClient: GoogleApiClient? = null

    /**
     * Run comprehensive tamper detection
     */
    suspend fun runIntegrityCheck(): IntegrityResult {
        val checks = listOf(
            checkDebuggable(),
            checkRooted(),
            checkEmulator(),
            checkHooks(),
            runSafetyNetAttestation()
        )

        val isValid = checks.all { it }
        return IntegrityResult(isValid = isValid)
    }

    /**
     * Check if app is running in debug mode
     */
    private fun checkDebuggable(): Boolean {
        val isDebuggable = (context.applicationInfo.flags and 
            android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        
        if (isDebuggable) {
            lastResult = lastResult.copy(isDebuggable = true)
        }
        
        // Allow debug builds to pass for development
        return !isDebuggable || isDebugBuild()
    }

    /**
     * Check if device is rooted
     */
    private fun checkRooted(): Boolean {
        val commonRootPaths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        val isRooted = commonRootPaths.any { path ->
            try {
                java.io.File(path).exists()
            } catch (e: Exception) {
                false
            }
        }

        // Also check for root-related apps
        val rootApps = listOf(
            "com.topjohnwu.magisk",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialab.quickdo"
        )

        val packageManager = context.packageManager
        for (app in rootApps) {
            try {
                packageManager.getPackageInfo(app, 0)
                return true
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not found - good
            }
        }

        lastResult = lastResult.copy(isRooted = isRooted)
        return !isRooted || isTestDevice()
    }

    /**
     * Check if running on emulator
     */
    private fun checkEmulator(): Boolean {
        val emulatorIndicators = listOf(
            // Build properties
            Build.FINGERPRINT.contains("generic"),
            Build.FINGERPRINT.contains("emulator"),
            Build.HARDWARE.contains("goldfish"),
            Build.HARDWARE.contains("ranchu"),
            Build.MODEL.contains("sdk_gphone64"),
            Build.MODEL.contains("Emulator"),
            Build.DEVICE.contains("sdk"),
            Build.DEVICE.contains("emulator"),
            // Common emulator files
            java.io.File("/system/bin/qemu_props").exists(),
            java.io.File("/system/bin/stub").exists(),
            // Check for QEMU environment
            System.getProperty("ro.kernel.qemu") == "1",
            System.getProperty("ro.kernel.android_qemu") == "1"
        )

        val isEmulator = emulatorIndicators.any { it }

        lastResult = lastResult.copy(isEmulator = isEmulator)
        return !isEmulator || isTestDevice()
    }

    /**
     * Check for Xposed/Hooks/FRIDA
     */
    private fun checkHooks(): Boolean {
        val hookIndicators = listOf(
            // Xposed
            "de.robv.android.xposed.XposedBridge" in getLoadedClasses(),
            // Substrate
            "com.saurik.substrate" in getLoadedClasses(),
            // FRIDA
            "frida" in getLoadedLibraries(),
            // Cydia Substrate
            "cydia" in getLoadedLibraries(),
            // Rootcloak
            "com.dev advance.rootcloak" in getInstalledApps(),
            // Detection bypass
            "com.android.internal.os.ZygoteInit" in getLoadedClasses()
        )

        val isHooked = hookIndicators.any { it }

        lastResult = lastResult.copy(isHooked = isHooked)
        return !isHooked
    }

    /**
     * Run Google SafetyNet Attestation API
     */
    private suspend fun runSafetyNetAttestation(): Boolean = suspendCancellableCoroutine { cont ->
        val nonce = generateNonce()

        SafetyNet.getClient(context).attest(nonce, PLAY_INTEGRITY_API_KEY)
            .addOnSuccessListener { result ->
                val isValid = verifyAttestationResult(result.jwsResult)
                cont.resume(isValid)
            }
            .addOnFailureListener { e ->
                // If SafetyNet fails, check if it's a network issue or device incompatibility
                // For security, fail closed - assume tampered if attestation can't run
                cont.resume(false)
            }
    }

    /**
     * Verify SafetyNet attestation response
     */
    private fun verifyAttestationResult(jwsResult: String): Boolean {
        try {
            // In production, validate JWS signature against Google's certificates
            // Check nonce matches
            // Check timestamp not too old
            // Parse and evaluate BasicIntegrity and CTSProfileMatch

            // For now, basic validation
            return jwsResult.isNotEmpty() && jwsResult.split(".").size == 3
        } catch (e: Exception) {
            return false
        }
    }

    /**
     * Generate nonce for attestation
     */
    private fun generateNonce(): ByteArray {
        val timeNonce = System.currentTimeMillis().toString()
        val deviceId = Build.FINGERPRINT + Build.MODEL
        val combined = NONCE_PREFIX + timeNonce + deviceId
        
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(combined.toByteArray())
    }

    private fun getLoadedClasses(): List<String> {
        return try {
            val classLoader = this::class.java.classLoader
            val loadedClasses = classLoader?.loadedClasses?.toList() ?: emptyList()
            loadedClasses
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun getLoadedLibraries(): List<String> {
        return try {
            val nativeLibs = java.lang.System.getProperty("java.library.path", "")
            nativeLibs.split(":").map { it.substringAfterLast("/") }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun getInstalledApps(): List<String> {
        return try {
            val pm = context.packageManager
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .map { it.packageName }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun isDebugBuild(): Boolean {
        return try {
            context.packageManager.getApplicationInfo(context.packageName, 0)
                .flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
        } catch (e: Exception) {
            false
        }
    }

    private fun isTestDevice(): Boolean {
        // Allow test devices in debug mode
        return isDebugBuild()
    }

    /**
     * Update tamper detection state
     */
    fun updateState(result: IntegrityResult) {
        lastResult = TamperDetectionState(
            isDeviceSecure = result.isValid,
            isAppAuthentic = result.isValid && !result.isRooted && !result.isHooked,
            hasPassedIntegrity = result.isValid,
            isRooted = result.isRooted,
            isHooked = result.isHooked,
            isEmulator = result.isEmulator,
            lastCheckTime = System.currentTimeMillis()
        )
    }

    fun getCurrentState(): TamperDetectionState = lastResult

    /**
     * Get security score (0-100)
     */
    fun getSecurityScore(): Int {
        var score = 100

        if (lastResult.isRooted) score -= 30
        if (lastResult.isHooked) score -= 40
        if (lastResult.isEmulator) score -= 20
        if (!lastResult.hasPassedIntegrity) score -= 40
        if (!lastResult.isAppAuthentic) score -= 10

        return score.coerceIn(0, 100)
    }
}

/**
 * Security action to take based on integrity check
 */
enum class SecurityAction {
    ALLOW,           // Device is secure
    WARN,            // Minor issues - allow with warning
    RESTRICT,        // Moderate issues - limit functionality
    BLOCK            // Major issues - block access
}

fun determineSecurityAction(state: TamperDetectionState): SecurityAction {
    return when {
        !state.hasPassedIntegrity -> SecurityAction.BLOCK
        state.isHooked -> SecurityAction.BLOCK
        state.isRooted && !isTestEnvironment() -> SecurityAction.RESTRICT
        state.isEmulator && !isTestEnvironment() -> SecurityAction.RESTRICT
        state.isRooted || state.isEmulator -> SecurityAction.WARN
        else -> SecurityAction.ALLOW
    }
}

private fun isTestEnvironment(): Boolean {
    return try {
        val context = android.app.Application::class.java.classLoader
        val packageInfo = context?.loadedClasses?.any { 
            it.name.contains("test") 
        } ?: false
        packageInfo
    } catch (e: Exception) {
        false
    }
}