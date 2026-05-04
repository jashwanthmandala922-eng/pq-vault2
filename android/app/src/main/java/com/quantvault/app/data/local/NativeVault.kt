package com.quantvault.app.data.local

import android.content.Context

class NativeVault private constructor() {
    companion object {
        private var instance: NativeVault? = null
        fun getInstance(): NativeVault {
            if (instance == null) { instance = NativeVault() }
            return instance!!
        }
    }

    init { System.loadLibrary("pqvault_core") }

    external fun nativeCreateVault(password: String): ByteArray
    external fun nativeUnlockVault(password: String, encryptedData: ByteArray): ByteArray
    external fun nativeAddEntry(vaultData: ByteArray, entryData: ByteArray): ByteArray
    external fun nativeGetEntries(vaultData: ByteArray): ByteArray
    external fun nativeDeleteEntry(vaultData: ByteArray, entryId: String): ByteArray

    fun createVault(password: String): Result<ByteArray> = try {
        Result.success(nativeCreateVault(password))
    } catch (e: Exception) { Result.failure(e) }

    fun unlockVault(password: String, encryptedData: ByteArray): Result<ByteArray> = try {
        Result.success(nativeUnlockVault(password, encryptedData))
    } catch (e: Exception) { Result.failure(e) }

    fun addEntry(vaultData: ByteArray, entry: VaultEntryDto): Result<ByteArray> = try {
        val entryJson = """{"id":"${entry.id}","title":"${entry.title}","url":"${entry.url}","username":"${entry.username}","password":"${entry.password}","notes":"${entry.notes}","createdAt":"${entry.createdAt}","favorite":${entry.favorite}}"""
        Result.success(nativeAddEntry(vaultData, entryJson.toByteArray()))
    } catch (e: Exception) { Result.failure(e) }

    fun deleteEntry(vaultData: ByteArray, entryId: String): Result<ByteArray> = try {
        Result.success(nativeDeleteEntry(vaultData, entryId))
    } catch (e: Exception) { Result.failure(e) }

    fun getEntries(vaultData: ByteArray): Result<List<VaultEntryDto>> = try {
        val result = nativeGetEntries(vaultData)
        val json = String(result, Charsets.UTF_8)
        if (json.isBlank() || json == "[]") Result.success(emptyList())
        else {
            val list = mutableListOf<VaultEntryDto>()
            try {
                val arr = org.json.JSONArray(json)
                for (i in 0 until arr.length()) {
                    val obj = arr.getJSONObject(i)
                    list.add(VaultEntryDto(
                        id = obj.optString("id", java.util.UUID.randomUUID().toString()),
                        title = obj.optString("title", ""),
                        url = obj.optString("url").ifEmpty { null },
                        username = obj.optString("username").ifEmpty { null },
                        password = obj.optString("password").ifEmpty { null },
                        notes = obj.optString("notes").ifEmpty { null },
                        createdAt = obj.optString("createdAt", java.time.Instant.now().toString()),
                        favorite = obj.optBoolean("favorite", false)
                    ))
                }
            } catch (e: Exception) { /* ignore parse errors */ }
            Result.success(list)
        }
    } catch (e: Exception) { Result.failure(e) }
}

data class VaultEntryDto(
    val id: String = java.util.UUID.randomUUID().toString(),
    val title: String,
    val url: String? = null,
    val username: String? = null,
    val password: String? = null,
    val notes: String? = null,
    val createdAt: String = java.time.Instant.now().toString(),
    val favorite: Boolean = false
)