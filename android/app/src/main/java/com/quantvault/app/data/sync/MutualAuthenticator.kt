package com.quantvault.app.data.sync

import android.util.Base64
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.X509EncodedKeySpec

data class MutualAuthState(
    val localDeviceId: String,
    val localPublicKey: ByteArray,
    val localPrivateKey: ByteArray,
    val peerDeviceId: String? = null,
    val peerPublicKey: ByteArray? = null,
    val sharedSecret: ByteArray? = null,
    val sasCode: String? = null,
    val isVerified: Boolean = false
)

class MutualAuthenticator {

    companion object {
        private const val DH_KEY_SIZE = 2048
        private const val SAS_LENGTH = 6
    }

    private val state: MutableMutualAuthState = MutableMutualAuthState()

    init {
        initializeDHKeyPair()
        state.localDeviceId = generateDeviceId()
    }

    private fun initializeDHKeyPair() {
        val keyGen = KeyGenerator.getInstance("DH")
        val dhPrime = BigInteger("00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497DCECEA1F2657C32F16E8C043EA" +
            "E7F9D8B1CFB1A0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", 16)
        val dhParams = DHParameterSpec(dhPrime, BigInteger("2"), 256)
        keyGen.initialize(dhParams, SecureRandom())
        val keyPair = keyGen.generateKeyPair()
        
        state.localPrivateKey = keyPair.private.encoded
        state.localPublicKey = keyPair.public.encoded
    }

    private fun generateDeviceId(): String {
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
        return Base64.encodeToString(random, Base64.NO_WRAP).take(16)
    }

    fun getLocalDeviceId(): String = state.localDeviceId

    fun getLocalPublicKey(): ByteArray = state.localPublicKey.copyOf()

    fun getLocalPublicKeyBase64(): String = Base64.encodeToString(state.localPublicKey, Base64.NO_WRAP)

    fun getQRContent(): String {
        return "${state.localDeviceId}|${getLocalPublicKeyBase64()}"
    }

    fun processPeerQR(qrContent: String): Boolean {
        return try {
            val parts = qrContent.split("|")
            if (parts.size != 2) return false

            state.peerDeviceId = parts[0]
            state.peerPublicKey = Base64.decode(parts[1], Base64.NO_WRAP)

            deriveSharedSecret()
            generateSAS()

            true
        } catch (e: Exception) {
            false
        }
    }

    private fun deriveSharedSecret() {
        try {
            val keyFactory = KeyFactory.getInstance("DH")
            val peerPublicKey = keyFactory.generatePublic(
                X509EncodedKeySpec(state.peerPublicKey!!)
            )

            val localPrivateKey = keyFactory.generatePrivate(
                X509EncodedKeySpec(state.localPrivateKey!!)
            )

            val keyAgreement = KeyAgreement.getInstance("DH")
            keyAgreement.init(localPrivateKey)
            keyAgreement.doPhase(peerPublicKey, true)

            val sharedSecret = keyAgreement.generateSecret()
            val hash = MessageDigest.getInstance("SHA-256")
            state.sharedSecret = hash.digest(sharedSecret)
        } catch (e: Exception) {
            state.sharedSecret = null
        }
    }

    private fun generateSAS() {
        val secret = state.sharedSecret ?: return
        val combined = secret + state.localDeviceId.toByteArray() + 
                       (state.peerDeviceId?.toByteArray() ?: byteArrayOf())

        val hash = MessageDigest.getInstance("SHA-256")
        val digest = hash.digest(combined)

        val numeric = digest.take(4).map { 
            (it.toInt() and 0xFF) % 1000000 
        }.joinToString("").take(SAS_LENGTH).padStart(SAS_LENGTH, '0')

        state.sasCode = numeric
    }

    fun getSASCode(): String? = state.sasCode

    fun verifyPeerSAS(peerSAS: String): Boolean {
        if (state.sasCode != peerSAS) return false
        state.isVerified = true
        return true
    }

    fun isVerified(): Boolean = state.isVerified

    fun getSharedSecret(): ByteArray? = state.sharedSecret

    fun reset() {
        state.peerDeviceId = null
        state.peerPublicKey = null
        state.sharedSecret = null
        state.sasCode = null
        state.isVerified = false
    }

    fun generateOutOfBandVerificationCode(): String {
        val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hash = MessageDigest.getInstance("SHA-256")
        val digest = hash.digest(random)
        
        val words = listOf(
            "apple", "brave", "crisp", "delta", "eagle", "flame", "grape", "house",
            "index", "jolly", "kite", "lemon", "maple", "noble", "ocean", "piano",
            "queen", "river", "solar", "tiger", "unity", "vivid", "water", "xenon",
            "yacht", "zebra", "amber", "blaze", "cloud", "dream", "earth", "frost"
        )

        val code = StringBuilder()
        for (i in 0 until 8) {
            val idx = (digest[i].toInt() and 0xFF) % words.size
            code.append(words[idx])
            if (i < 7) code.append("-")
        }
        return code.toString().uppercase()
    }

    private class MutableMutualAuthState(
        var localDeviceId: String = "",
        var localPublicKey: ByteArray = byteArrayOf(),
        var localPrivateKey: ByteArray = byteArrayOf(),
        var peerDeviceId: String? = null,
        var peerPublicKey: ByteArray? = null,
        var sharedSecret: ByteArray? = null,
        var sasCode: String? = null,
        var isVerified: Boolean = false
    )
}