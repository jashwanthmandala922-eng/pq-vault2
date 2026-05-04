package com.quantvault.app.data.repository

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.floor

@Singleton
class TOTPRepository @Inject constructor() {

    fun generateTOTP(secret: String, digits: Int = 6, period: Int = 30): String {
        return try {
            val key = Base32.decode(secret.uppercase().replace(" ", ""))
            val time = floor(System.currentTimeMillis() / 1000.0 / period).toLong()
            val hash = hmacSha1(key, ByteBuffer.allocate(8).putLong(time).array())
            val offset = hash[hash.size - 1].toInt() and 0x0F
            val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
                    ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                    ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                    (hash[offset + 3].toInt() and 0xFF)
            val otp = binary % Math.pow(10.0, digits.toDouble()).toInt()
            otp.toString().padStart(digits, '0')
        } catch (e: Exception) {
            "------"
        }
    }

    fun getRemainingSeconds(period: Int = 30): Int {
        return period - (floor(System.currentTimeMillis() / 1000.0) % period).toInt()
    }

    private fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(data)
    }
}

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val TABLE = ALPHABET.toCharArray()

    fun decode(input: String): ByteArray {
        val cleanInput = input.replace("=", "").uppercase()
        val output = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0

        for (char in cleanInput) {
            val value = ALPHABET.indexOf(char)
            if (value < 0) continue
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                output.add((buffer shr (bitsLeft - 8)).toByte())
                bitsLeft -= 8
            }
        }
        return output.toByteArray()
    }
}