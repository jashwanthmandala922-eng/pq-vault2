package com.quantvault.app.data.local

import android.content.Context
import android.content.SharedPreferences

class SecurePreferences(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("pq_vault_secure", Context.MODE_PRIVATE)

    var vaultData: ByteArray?
        get() = prefs.getString("vault_data", null)?.let { android.util.Base64.decode(it, android.util.Base64.DEFAULT) }
        set(value) = prefs.edit().putString("vault_data", value?.let { android.util.Base64.encodeToString(it, android.util.Base64.DEFAULT) }).apply()

    var oauthToken: String?
        get() = prefs.getString("oauth_token", null)
        set(value) = prefs.edit().putString("oauth_token", value).apply()

    var biometricEnabled: Boolean
        get() = prefs.getBoolean("biometric_enabled", true)
        set(value) = prefs.edit().putBoolean("biometric_enabled", value).apply()

    var autoLockTimeout: Int
        get() = prefs.getInt("auto_lock_timeout", 300)
        set(value) = prefs.edit().putInt("auto_lock_timeout", value).apply()

    var clearClipboard: Boolean
        get() = prefs.getBoolean("clear_clipboard", true)
        set(value) = prefs.edit().putBoolean("clear_clipboard", value).apply()

    var lastSyncTime: Long
        get() = prefs.getLong("last_sync_time", 0)
        set(value) = prefs.edit().putLong("last_sync_time", value).apply()

    var localKeySalt: ByteArray?
        get() = prefs.getString("local_key_salt", null)?.let { android.util.Base64.decode(it, android.util.Base64.DEFAULT) }
        set(value) = prefs.edit().putString("local_key_salt", value?.let { android.util.Base64.encodeToString(it, android.util.Base64.DEFAULT) }).apply()

    var encryptedLocalKey: ByteArray?
        get() = prefs.getString("encrypted_local_key", null)?.let { android.util.Base64.decode(it, android.util.Base64.DEFAULT) }
        set(value) = prefs.edit().putString("encrypted_local_key", value?.let { android.util.Base64.encodeToString(it, android.util.Base64.DEFAULT) }).apply()

    var authMode: String
        get() = prefs.getString("auth_mode", "oauth_only") ?: "oauth_only"
        set(value) = prefs.edit().putString("auth_mode", value).apply()

    var isPinSetup: Boolean
        get() = prefs.getBoolean("pin_setup", false)
        set(value) = prefs.edit().putBoolean("pin_setup", value).apply()

    var biometricKeyId: String?
        get() = prefs.getString("biometric_key_id", null)
        set(value) = prefs.edit().putString("biometric_key_id", value).apply()

    fun clearAll() {
        prefs.edit().clear().apply()
    }
}