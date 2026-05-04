package com.quantvault.app.data.local

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class VaultEntry(
    val id: String = java.util.UUID.randomUUID().toString(),
    val title: String,
    val url: String? = null,
    val username: String? = null,
    val password: String? = null,
    val notes: String? = null,
    val createdAt: String = java.time.Instant.now().toString(),
    val favorite: Boolean = false,
    val entryType: String = "login",
    val customFields: List<CustomField> = emptyList()
)

data class CustomField(
    val name: String,
    val value: String,
    val isHidden: Boolean = false
)

data class EncryptedVaultEntry(
    val id: EncryptedField,
    val title: EncryptedField,
    val url: EncryptedField?,
    val username: EncryptedField?,
    val password: EncryptedField,
    val notes: EncryptedField?,
    val createdAt: EncryptedField,
    val favorite: EncryptedField,
    val entryType: EncryptedField,
    val customFields: List<EncryptedCustomField>
)

data class EncryptedCustomField(
    val name: EncryptedField,
    val value: EncryptedField,
    val isHidden: EncryptedField
)

data class EncryptedField(
    val cipherText: ByteArray,
    val nonce: ByteArray,
    val tag: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedField

        if (!cipherText.contentEquals(other.cipherText)) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (!tag.contentEquals(other.tag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cipherText.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + tag.contentHashCode()
        return result
    }
}

class MetadataEncryptor(sessionKey: ByteArray) {
    private val key: SecretKeySpec
    private val gcmTagLength = 128
    private val nonceSize = 12

    companion object {
        private fun deriveKeyFromMaster(masterKey: ByteArray, context: String): ByteArray {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(javax.crypto.spec.SecretKeySpec(masterKey, "HmacSHA256"))
            mac.update(context.toByteArray())
            return mac.doFinal().copyOf(32)
        }
    }

    init {
        val keyBytes = deriveKeyFromMaster(sessionKey, "metadata-encryption")
        this.key = SecretKeySpec(keyBytes, "AES")
    }

    fun encryptField(plaintext: String): EncryptedField {
        val nonceBytes = ByteArray(nonceSize).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(gcmTagLength, nonceBytes))
        
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val cipherText = cipher.doFinal(plaintextBytes)
        
        // GCM appends tag to ciphertext - split them
        val actualCipherText = cipherText.copyOfRange(0, cipherText.size - 16)
        val authTag = cipherText.copyOfRange(cipherText.size - 16, cipherText.size)
        
        return EncryptedField(actualCipherText, nonceBytes, authTag)
    }

    fun decryptField(field: EncryptedField): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(gcmTagLength, field.nonce)
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
        
        val combined = field.cipherText + field.tag
        val plaintext = cipher.doFinal(combined)
        
        return String(plaintext, Charsets.UTF_8)
    }

    fun encryptEntry(entry: VaultEntry): EncryptedVaultEntry {
        return EncryptedVaultEntry(
            id = encryptField(entry.id),
            title = encryptField(entry.title),
            url = entry.url?.let { encryptField(it) },
            username = entry.username?.let { encryptField(it) },
            password = encryptField(entry.password ?: ""),
            notes = entry.notes?.let { encryptField(it) },
            createdAt = encryptField(entry.createdAt),
            favorite = encryptField(entry.favorite.toString()),
            entryType = encryptField(entry.entryType),
            customFields = entry.customFields.map { cf ->
                EncryptedCustomField(
                    name = encryptField(cf.name),
                    value = encryptField(cf.value),
                    isHidden = encryptField(cf.isHidden.toString())
                )
            }
        )
    }

    fun decryptEntry(encrypted: EncryptedVaultEntry): VaultEntry {
        return VaultEntry(
            id = decryptField(encrypted.id),
            title = decryptField(encrypted.title),
            url = encrypted.url?.let { decryptField(it) },
            username = encrypted.username?.let { decryptField(it) },
            password = decryptField(encrypted.password).ifEmpty { null },
            notes = encrypted.notes?.let { decryptField(it) },
            createdAt = decryptField(encrypted.createdAt),
            favorite = decryptField(encrypted.favorite).toBoolean(),
            entryType = decryptField(encrypted.entryType),
            customFields = encrypted.customFields.map { cf ->
                CustomField(
                    name = decryptField(cf.name),
                    value = decryptField(cf.value),
                    isHidden = decryptField(cf.isHidden).toBoolean()
                )
            }
        )
    }

    fun serializeEncryptedEntry(encrypted: EncryptedVaultEntry): ByteArray {
        val output = ByteArrayOutputStream()
        
        fun writeField(field: EncryptedField) {
            output.write(field.nonce.size)
            output.write(field.nonce)
            output.write(field.cipherText.size)
            output.write(field.cipherText)
            output.write(field.tag.size)
            output.write(field.tag)
        }
        
        fun writeOptional(field: EncryptedField?) {
            output.write(if (field != null) 1 else 0)
            field?.let { writeField(it) }
        }
        
        writeField(encrypted.id)
        writeField(encrypted.title)
        writeOptional(encrypted.url)
        writeOptional(encrypted.username)
        writeField(encrypted.password)
        writeOptional(encrypted.notes)
        writeField(encrypted.createdAt)
        writeField(encrypted.favorite)
        writeField(encrypted.entryType)
        
        output.write(encrypted.customFields.size)
        encrypted.customFields.forEach { cf ->
            writeField(cf.name)
            writeField(cf.value)
            writeField(cf.isHidden)
        }
        
        return output.toByteArray()
    }

    fun deserializeEncryptedEntry(data: ByteArray): EncryptedVaultEntry {
        val input = ByteArrayInputStream(data)
        
        fun readField(): EncryptedField {
            val nonceLen = input.read()
            val nonce = ByteArray(nonceLen).also { input.read(it) }
            val cipherLen = input.read() * 256 + input.read()
            val cipherText = ByteArray(cipherLen).also { input.read(it) }
            val tagLen = input.read()
            val tag = ByteArray(tagLen).also { input.read(it) }
            return EncryptedField(cipherText, nonce, tag)
        }
        
        fun readOptional(): EncryptedField? {
            return if (input.read() == 1) readField() else null
        }
        
        val id = readField()
        val title = readField()
        val url = readOptional()
        val username = readOptional()
        val password = readField()
        val notes = readOptional()
        val createdAt = readField()
        val favorite = readField()
        val entryType = readField()
        
        val customFieldCount = input.read()
        val customFields = (0 until customFieldCount).map {
            EncryptedCustomField(
                name = readField(),
                value = readField(),
                isHidden = readField()
            )
        }
        
        return EncryptedVaultEntry(
            id, title, url, username, password, notes,
            createdAt, favorite, entryType, customFields
        )
    }
}

class ByteArrayOutputStream(private val buffer: MutableList<Byte> = mutableListOf()) {
    fun write(b: Int) { buffer.add(b.toByte()) }
    fun write(b: ByteArray) { buffer.addAll(b.toList()) }
    fun toByteArray() = buffer.toByteArray()
}

class ByteArrayInputStream(private val bytes: ByteArray, private var position: Int = 0) {
    fun read(): Int = if (position < bytes.size) bytes[position++].toInt() and 0xFF else -1
    fun read(b: ByteArray) {
        bytes.copyInto(b, 0, position, (position + b.size).coerceAtMost(bytes.size))
        position += b.size
    }
}