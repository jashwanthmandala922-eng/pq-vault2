package com.quantvault.app.data.sync

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.KeyFactory
import javax.crypto.spec.X509EncodedKeySpec

class PFSKeyManager(
    private val baseSharedSecret: ByteArray
) {
    private var messageCounter: Long = 0
    private var chainKey: ByteArray = baseSharedSecret.copyOf()
    private val usedMessageKeys = mutableSetOf<Long>()

    companion object {
        private const val KEY_SIZE = 32
        private const val NONCE_SIZE = 12
        private const val GCM_TAG_SIZE = 128
    }

    fun generateMessageKey(): Pair<SecretKey, ByteArray> {
        messageCounter++

        while (usedMessageKeys.contains(messageCounter)) {
            messageCounter++
        }

        chainKey = deriveChainKey(chainKey, messageCounter)
        val messageKey = deriveMessageKey(chainKey, messageCounter)

        val keySpec = SecretKeySpec(messageKey.copyOf(KEY_SIZE), "AES")
        val nonce = ByteArray(NONCE_SIZE).also { SecureRandom().nextBytes(it) }

        return keySpec to nonce
    }

    private fun deriveChainKey(chainKey: ByteArray, counter: Long): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(chainKey, "HmacSHA256"))
        mac.update("chain_key".toByteArray())
        mac.update(counter.toString().toByteArray())
        mac.update("pfs_ratchet".toByteArray())
        return mac.doFinal()
    }

    private fun deriveMessageKey(chainKey: ByteArray, counter: Long): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(chainKey, "HmacSHA256"))
        mac.update("message_key".toByteArray())
        mac.update(counter.toString().toByteArray())
        return mac.doFinal()
    }

    fun encryptMessage(plaintext: ByteArray): ByteArray {
        val (key, nonce) = generateMessageKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_SIZE, nonce))
        val ciphertext = cipher.doFinal(plaintext)

        return buildPacket(messageCounter, nonce, ciphertext)
    }

    fun decryptMessage(packet: ByteArray): ByteArray? {
        val (counter, nonce, ciphertext) = parsePacket(packet) ?: return null

        if (usedMessageKeys.contains(counter)) {
            return null
        }

        usedMessageKeys.add(counter)

        val chainKeyForCounter = deriveChainKeyForCounter(counter)
        val messageKey = deriveMessageKey(chainKeyForCounter, counter)
        val keySpec = SecretKeySpec(messageKey.copyOf(KEY_SIZE), "AES")

        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_SIZE, nonce))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            usedMessageKeys.remove(counter)
            null
        }
    }

    private fun deriveChainKeyForCounter(counter: Long): ByteArray {
        var chain = baseSharedSecret.copyOf()
        for (i in 1..counter) {
            chain = deriveChainKey(chain, i)
        }
        return chain
    }

    private fun buildPacket(counter: Long, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val packet = ByteArrayOutputStream()
        packet.writeLong(counter)
        packet.write(nonce)
        packet.write(ciphertext)
        return packet.toByteArray()
    }

    private fun parsePacket(packet: ByteArray): Triple<Long, ByteArray, ByteArray>? {
        if (packet.size < 20) return null

        val counter = packet.toLong()
        val nonce = packet.copyOfRange(8, 8 + NONCE_SIZE)
        val ciphertext = packet.copyOfRange(8 + NONCE_SIZE, packet.size)
        return Triple(counter, nonce, ciphertext)
    }

    fun getCurrentCounter(): Long = messageCounter

    fun importCounter(counter: Long) {
        messageCounter = counter
    }

    class ByteArrayOutputStream {
        private val bytes = mutableListOf<Byte>()
        fun write(b: Int) { bytes.add(b.toByte()) }
        fun write(b: ByteArray) { bytes.addAll(b.toList()) }
        fun writeLong(l: Long) {
            bytes.addAll(l.toString().toByteArray().toList())
        }
        fun toByteArray() = bytes.toByteArray()
    }

    private fun Long.toByteArray(): ByteArray {
        return this.toString().toByteArray()
    }

    private fun ByteArray.toLong(): Long {
        return String(this).toLongOrNull() ?: 0L
    }
}

class PFSChannel(
    private val keyManager: PFSKeyManager
) {
    fun sendMessage(data: ByteArray): ByteArray {
        return keyManager.encryptMessage(data)
    }

    fun receiveMessage(packet: ByteArray): ByteArray? {
        return keyManager.decryptMessage(packet)
    }
}

class DualRatchetPFS(
    private val rootKey: ByteArray,
    private val peerPublicKey: ByteArray
) {
    private var sendingChainKey: ByteArray
    private var receivingChainKey: ByteArray
    private var sendingRatchetKey: ByteArray
    private var receivingRatchetKey: ByteArray = peerPublicKey

    companion object {
        private const val DH_PARAMS = "prime:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497DCECEA1F2657C32F16E8C043EA" +
            "E7F9D8B1CFB1A0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0"
    private const val GENERATOR = "2"
    }

    init {
        val keyPair = generateEphemeralDHKeyPair()
        sendingRatchetKey = keyPair.second

        val dh = KeyAgreement.getInstance("DH")
        dh.init(keyPair.first)
        val peerKey = KeyFactory.getInstance("DH").generatePublic(
            X509EncodedKeySpec(peerPublicKey)
        )
        dh.doPhase(peerKey, true)

        val sharedSecret = dh.generateSecret()
        val rootDerived = deriveRootKey(rootKey, sharedSecret)
        sendingChainKey = rootDerived.first
        receivingChainKey = rootDerived.second
    }

    private fun generateEphemeralDHKeyPair(): Pair<java.security.KeyPair, ByteArray> {
        val keyGen = KeyGenerator.getInstance("DH")
        keyGen.initialize(2048, SecureRandom())
        val keyPair = keyGen.generateKeyPair()
        return keyPair to keyPair.public.encoded
    }

    private fun deriveRootKey(rootKey: ByteArray, dhOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rootKey, "HmacSHA256"))
        mac.update("root_ratchet".toByteArray())
        mac.update(dhOutput)
        val output = mac.doFinal()
        return output.copyOf(32) to output.copyOfRange(32, 64)
    }

    private fun deriveChainKey(chainKey: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(chainKey, "HmacSHA256"))
        mac.update("chain_step".toByteArray())
        return mac.doFinal()
    }

    fun encrypt(data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sendingChainKey, "HmacSHA256"))
        mac.update(data)
        val messageKey = mac.doFinal()

        val key = SecretKeySpec(messageKey.copyOf(32), "AES")
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(data)

        sendingChainKey = deriveChainKey(sendingChainKey)

        return nonce + ciphertext
    }

    fun decrypt(data: ByteArray): ByteArray? {
        if (data.size < 12) return null

        val nonce = data.copyOfRange(0, 12)
        val ciphertext = data.copyOfRange(12, data.size)

        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(receivingChainKey, "HmacSHA256"))
        val messageKey = mac.doFinal()

        val key = SecretKeySpec(messageKey.copyOf(32), "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))

        return try {
            cipher.doFinal(ciphertext).also {
                receivingChainKey = deriveChainKey(receivingChainKey)
            }
        } catch (e: Exception) {
            null
        }
    }

    fun getSendingPublicKey(): ByteArray = sendingRatchetKey
}