package com.quantvault.app.data.sync

import android.util.Base64
import com.quantvault.app.data.local.NativeVault
import com.quantvault.app.data.local.SecurePreferences
import com.quantvault.app.data.local.VaultEntry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import javax.inject.Inject
import javax.inject.Singleton

data class SyncPeer(
    val deviceId: String,
    val displayName: String,
    val ipAddress: String,
    val port: Int,
    val lastSeen: Long = System.currentTimeMillis()
)

data class SyncMessage(
    val type: String,
    val senderId: String,
    val payload: String,
    val timestamp: Long = System.currentTimeMillis()
)

@Singleton
class SyncRepository @Inject constructor(
    private val nativeVault: NativeVault,
    private val securePreferences: SecurePreferences,
    @ApplicationContext private val context: android.content.Context
) {
    private val mutualAuthenticator = MutualAuthenticator()
    private val discoveredPeers = mutableListOf<SyncPeer>()
    private var pfsKeyManager: PFSKeyManager? = null
    private var pfsChannel: PFSChannel? = null

    companion object {
        private const val UDP_PORT = 53535
        private const val TCP_PORT = 53536
        private const val DISCOVERY_INTERVAL = 5000L
        private const val BUFFER_SIZE = 65536
    }

    fun getLocalDeviceId(): String = mutualAuthenticator.getLocalDeviceId()

    fun getQRContent(): String = mutualAuthenticator.getQRContent()

    fun generateQRBitmap() = QRCodeGenerator.generateQRCode(getQRContent())

    fun startPairingScan(qrContent: String): Boolean {
        return mutualAuthenticator.processPeerQR(qrContent)
    }

    fun getSASCode(): String? = mutualAuthenticator.getSASCode()

    fun verifySAS(peerSAS: String): Boolean {
        return mutualAuthenticator.verifyPeerSAS(peerSAS)
    }

    fun isMutualAuthVerified(): Boolean = mutualAuthenticator.isVerified()

    fun getSharedSecret(): ByteArray? = mutualAuthenticator.getSharedSecret()

    fun initializePFS() {
        val secret = mutualAuthenticator.getSharedSecret() ?: return
        pfsKeyManager = PFSKeyManager(secret)
        pfsChannel = PFSChannel(pfsKeyManager!!)
    }

    fun getMessageCounter(): Long = pfsKeyManager?.getCurrentCounter() ?: 0

    fun encryptWithPFS(data: ByteArray): ByteArray {
        return pfsKeyManager?.encryptMessage(data) ?: encryptWithLegacy(data)
    }

    fun decryptWithPFS(packet: ByteArray): ByteArray? {
        return pfsKeyManager?.decryptMessage(packet) ?: decryptWithLegacy(packet)
    }

    private fun encryptWithLegacy(data: ByteArray): ByteArray {
        val secret = getSharedSecret() ?: return data
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(secret.copyOf(32), "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    private fun decryptWithLegacy(data: ByteArray): ByteArray? {
        return try {
            if (data.size < 12) return null
            val iv = data.copyOfRange(0, 12)
            val ciphertext = data.copyOfRange(12, data.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(getSharedSecret()!!.copyOf(32), "AES")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    suspend fun discoverPeers(): List<SyncPeer> = withContext(Dispatchers.IO) {
        val peers = mutableListOf<SyncPeer>()

        try {
            val socket = DatagramSocket(UDP_PORT)
            socket.soTimeout = 3000

            val broadcastMessage = "PQVAULT_DISCOVER|${getLocalDeviceId()}".toByteArray()
            val broadcastAddress = InetAddress.getByName("255.255.255.255")
            val broadcastPacket = DatagramPacket(broadcastMessage, broadcastMessage.size, broadcastAddress, UDP_PORT)
            socket.send(broadcastPacket)

            val buffer = ByteArray(BUFFER_SIZE)
            val endTime = System.currentTimeMillis() + 3000

            while (System.currentTimeMillis() < endTime) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val response = String(packet.data, 0, packet.length)
                    val parts = response.split("|")

                    if (parts.size >= 4 && parts[0] == "PQVAULT_RESPONSE") {
                        val peer = SyncPeer(
                            deviceId = parts[1],
                            displayName = parts[2],
                            ipAddress = packet.address.hostAddress ?: "",
                            port = parts[3].toIntOrNull() ?: TCP_PORT
                        )
                        if (peer.deviceId != getLocalDeviceId()) {
                            peers.add(peer)
                        }
                    }
                } catch (e: Exception) {
                    break
                }
            }

            socket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }

        discoveredPeers.clear()
        discoveredPeers.addAll(peers)
        peers
    }

    suspend fun initiateSyncWithPeer(peer: SyncPeer): Result<Unit> = withContext(Dispatchers.IO) {
        if (!isMutualAuthVerified()) {
            return@withContext Result.failure(Exception("Mutual authentication not completed"))
        }

        initializePFS()

        try {
            val socket = Socket(peer.ipAddress, peer.port)
            val writer = OutputStreamWriter(socket.getOutputStream())
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))

            val authChallenge = mutualAuthenticator.getSharedSecret()?.let {
                Base64.encodeToString(it, Base64.NO_WRAP)
            } ?: ""

            writer.write("SYNC_INIT|${getLocalDeviceId()}|$authChallenge|PFS\n")
            writer.flush()

            val response = reader.readLine()
            if (response?.startsWith("SYNC_ACK") != true) {
                return@withContext Result.failure(Exception("Sync not acknowledged"))
            }

            val vaultData = nativeVault.exportVault() ?: return@withContext Result.failure(Exception("No vault data"))

            val encryptedPayload = encryptWithPFS(vaultData)

            val counter = getMessageCounter()
            writer.write("SYNC_DATA_PFS|$counter|${encryptedPayload.size}\n")
            writer.write(Base64.encodeToString(encryptedPayload, Base64.NO_WRAP))
            writer.flush()

            val ack = reader.readLine()
            if (ack?.startsWith("SYNC_COMPLETE") == true) {
                pfsKeyManager?.let {
                    val keyRotationInfo = "KEY_ROTATION|${getMessageCounter()}"
                    securePreferences.lastSyncTime = System.currentTimeMillis()
                }
                Result.success(Unit)
            } else {
                Result.failure(Exception("Sync failed"))
            }.also {
                writer.close()
                reader.close()
                socket.close()
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun receiveSync(): Result<ByteArray> = withContext(Dispatchers.IO) {
        try {
            val serverSocket = ServerSocket(TCP_PORT)
            serverSocket.soTimeout = 30000

            val clientSocket = serverSocket.accept()
            val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
            val writer = OutputStreamWriter(clientSocket.getOutputStream())

            val request = reader.readLine()
            val parts = request.split("|")

            if (parts.size < 3 || parts[0] != "SYNC_INIT") {
                return@withContext Result.failure(Exception("Invalid sync request"))
            }

            val peerChallenge = parts[2]
            val localChallenge = mutualAuthenticator.getSharedSecret()?.let {
                Base64.encodeToString(it, Base64.NO_WRAP)
            } ?: ""

            if (peerChallenge != localChallenge) {
                writer.write("SYNC_REJECT|challenge_mismatch\n")
                writer.flush()
                return@withContext Result.failure(Exception("Challenge mismatch - potential MitM"))
            }

            val pfsEnabled = parts.getOrNull(3) == "PFS"

            writer.write("SYNC_ACK|${getLocalDeviceId()}\n")
            writer.flush()

            if (pfsEnabled) {
                initializePFS()
            }

            val dataHeader = reader.readLine()
            val dataParts = dataHeader.split("|")

            if (dataParts[0] == "SYNC_DATA_PFS" && pfsEnabled) {
                val counter = dataParts.getOrNull(1)?.toLongOrNull() ?: 0
                pfsKeyManager?.importCounter(counter)

                val dataSize = dataParts.getOrNull(2)?.toIntOrNull() ?: return@withContext Result.failure(Exception("Invalid data size"))

                val encryptedData = reader.readLines().joinToString("").let {
                    Base64.decode(it.substring(0, dataSize), Base64.NO_WRAP)
                }

                val decryptedVault = decryptWithPFS(encryptedData)
                if (decryptedVault != null) {
                    writer.write("SYNC_COMPLETE\n")
                    writer.flush()
                } else {
                    return@withContext Result.failure(Exception("PFS decryption failed"))
                }
            } else if (dataParts.size >= 2 && dataParts[0] == "SYNC_DATA") {
                val dataSize = dataParts[1].toIntOrNull() ?: return@withContext Result.failure(Exception("Invalid data size"))
                val encryptedData = reader.readLines().joinToString("").let {
                    Base64.decode(it.substring(0, dataSize), Base64.NO_WRAP)
                }
                val decryptedVault = decryptSyncPayload(encryptedData)
                if (decryptedVault != null) {
                    writer.write("SYNC_COMPLETE\n")
                    writer.flush()
                }
            } else {
                return@withContext Result.failure(Exception("Unknown data format"))
            }

            reader.close()
            writer.close()
            clientSocket.close()
            serverSocket.close()

            Result.success(decryptedVault)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun encryptSyncPayload(data: ByteArray): ByteArray {
        val secret = getSharedSecret() ?: return data
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }

        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = javax.crypto.spec.SecretKeySpec(secret.copyOf(32), "AES")
        val gcmSpec = javax.crypto.spec.GCMParameterSpec(128, iv)
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    private fun decryptSyncPayload(data: ByteArray): ByteArray? {
        return try {
            val secret = getSharedSecret() ?: return null
            if (data.size < 12) return null

            val iv = data.copyOfRange(0, 12)
            val ciphertext = data.copyOfRange(12, data.size)

            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = javax.crypto.spec.SecretKeySpec(secret.copyOf(32), "AES")
            val gcmSpec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    fun resetPairing() {
        mutualAuthenticator.reset()
    }

    fun getDiscoveredPeers(): List<SyncPeer> = discoveredPeers.toList()
}