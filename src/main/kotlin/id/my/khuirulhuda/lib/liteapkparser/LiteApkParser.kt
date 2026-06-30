package id.my.khuirulhuda.lib.liteapkparser

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.HashMap

class LiteApkParser {

    data class TriageResult(
        val score: Int,
        val status: TriageStatus,
        val dangerousPermissions: List<String>,
        val highEntropyDetected: Boolean,
        val xorObfuscationDetected: Boolean,
        val matchedPatterns: List<String>,
        val extractedEvidence: List<String>
    )

    enum class TriageStatus { SAFE, GREY_AREA, MALICIOUS }

    fun analyzeApk(file: File): TriageResult {
        return file.inputStream().use { inputStream ->
            analyzeApkStream(inputStream)
        }
    }

    fun analyzeApkStream(inputStream: InputStream): TriageResult {
        val zipStream = LiteZipInputStream(inputStream)
        val resultBuilder = AnalysisResultBuilder()

        try {
            while (true) {
                val entry = zipStream.nextEntry() ?: break
                val name = entry.name
                if (name == "AndroidManifest.xml") {
                    val data = zipStream.readEntryData(entry)
                    if (data != null) {
                        try {
                            val manifestInfo = BinaryXmlParser(data).parse()
                            resultBuilder.addManifestInfo(manifestInfo)
                        } catch (e: Exception) {
                            // Suppress XML parsing exception
                        }
                    }
                } else if (name.startsWith("classes") && name.endsWith(".dex")) {
                    val data = zipStream.readEntryData(entry)
                    if (data != null) {
                        try {
                            scanDexBytes(data, resultBuilder)
                        } catch (e: Exception) {
                            // Suppress DEX parsing exception
                        }
                    }
                } else {
                    zipStream.skipEntryData(entry)
                }
            }
        } catch (e: Exception) {
            // End of stream or parsing issues
        }

        return resultBuilder.build()
    }

    private fun scanDexBytes(dexBytes: ByteArray, resultBuilder: AnalysisResultBuilder) {
        val bais = ByteArrayInputStream(dexBytes)
        val offsetStream = OffsetInputStream(bais)

        val candidateKeys = mutableListOf<String>()
        val candidateCiphertexts = mutableListOf<String>()

        // 1. Read header (we need at least 64 bytes)
        val header = ByteArray(64)
        var totalRead = 0
        while (totalRead < 64) {
            val r = offsetStream.read(header, totalRead, 64 - totalRead)
            if (r <= 0) return
            totalRead += r
        }

        val stringIdsSize = readInt(header, 56)
        val stringIdsOffset = readInt(header, 60)

        if (stringIdsSize <= 0 || stringIdsOffset < 64) {
            return
        }

        // Skip to stringIdsOffset
        val toSkip = stringIdsOffset.toLong() - offsetStream.offset
        if (toSkip > 0) {
            skipFully(offsetStream, toSkip)
        }

        // Read string IDs
        val stringIdsBytes = ByteArray(stringIdsSize * 4)
        var idsRead = 0
        while (idsRead < stringIdsBytes.size) {
            val r = offsetStream.read(stringIdsBytes, idsRead, stringIdsBytes.size - idsRead)
            if (r <= 0) return
            idsRead += r
        }

        val stringOffsets = IntArray(stringIdsSize)
        for (i in 0 until stringIdsSize) {
            stringOffsets[i] = readInt(stringIdsBytes, i * 4)
        }

        // Sort offsets chronologically
        val sortedOffsets = stringOffsets.clone()
        sortedOffsets.sort()

        var nextStringIdx = 0
        val xorDetector = XorOpcodeDetector()

        while (true) {
            val currentOffset = offsetStream.offset

            if (nextStringIdx < sortedOffsets.size && currentOffset == sortedOffsets[nextStringIdx].toLong()) {
                readUleb128(offsetStream)
                val stringBytes = readMutf8Bytes(offsetStream)
                val decodedString = decodeMutf8(stringBytes)

                val trimmed = decodedString.trim()
                if (trimmed.length in listOf(16, 24, 32)) {
                    candidateKeys.add(trimmed)
                }
                if (trimmed.length >= 20 && Deobfuscator.decodeBase64Pure(trimmed) != null) {
                    candidateCiphertexts.add(trimmed)
                }

                runStringScanners(decodedString, resultBuilder)

                nextStringIdx++
                // Skip any duplicate offsets
                while (nextStringIdx < sortedOffsets.size && sortedOffsets[nextStringIdx] <= offsetStream.offset) {
                    nextStringIdx++
                }
            } else {
                val nextOffset = if (nextStringIdx < sortedOffsets.size) sortedOffsets[nextStringIdx].toLong() else -1L
                if (nextOffset != -1L) {
                    val bytesToRead = (nextOffset - currentOffset).toInt()
                    if (bytesToRead > 0) {
                        val tempBuf = ByteArray(minOf(8192, bytesToRead))
                        var remaining = bytesToRead
                        while (remaining > 0) {
                            val chunk = minOf(remaining, tempBuf.size)
                            val read = offsetStream.read(tempBuf, 0, chunk)
                            if (read <= 0) break
                            for (i in 0 until read) {
                                if (xorDetector.feed(tempBuf[i].toInt() and 0xFF)) {
                                    resultBuilder.xorObfuscationDetected = true
                                }
                            }
                            remaining -= read
                        }
                    }
                } else {
                    val tempBuf = ByteArray(8192)
                    while (true) {
                        val read = offsetStream.read(tempBuf)
                        if (read <= 0) break
                        for (i in 0 until read) {
                            if (xorDetector.feed(tempBuf[i].toInt() and 0xFF)) {
                                resultBuilder.xorObfuscationDetected = true
                            }
                        }
                    }
                    break
                }
            }
        }

        println("  [DEX CANDIDATES] keys: ${candidateKeys.size}, ciphertexts: ${candidateCiphertexts.size}")
        if (candidateKeys.isNotEmpty() && candidateCiphertexts.isNotEmpty()) {
            for (ciphertext in candidateCiphertexts) {
                Deobfuscator.tryDecryptAes(ciphertext, candidateKeys, resultBuilder) { dec ->
                    runStringScannersInternal(dec, resultBuilder, runDecoder = false)
                }
            }
        }
        Deobfuscator.scanShortArrays(dexBytes, resultBuilder) { dec ->
            runStringScannersInternal(dec, resultBuilder, runDecoder = false)
        }
    }

    private fun runStringScanners(s: String, resultBuilder: AnalysisResultBuilder) {
        runStringScannersInternal(s, resultBuilder, runDecoder = true)
    }

    private fun runStringScannersInternal(s: String, resultBuilder: AnalysisResultBuilder, runDecoder: Boolean) {
        if (s.contains("javax/crypto/Cipher") ||
            s.contains("javax/crypto/spec/SecretKeySpec") ||
            s.contains("android/util/Base64")
        ) {
            resultBuilder.cryptoApiDetected = true
        }

        if (s.length >= 8) {
            val entropy = calculateShannonEntropy(s)
            if (entropy > 6.5) {
                resultBuilder.highEntropyDetected = true
            }
        }

        // Silent Install / Dropper
        if (s.contains("pm install") ||
            s.contains("cmd package install") ||
            s.contains("application/vnd.android.package-archive") ||
            s.contains("PackageInstaller\$Session") ||
            s.contains("DexClassLoader") ||
            s.contains("PathClassLoader")
        ) {
            if (s == "Ldalvik/system/PathClassLoader;" || s == "dalvik.system.PathClassLoader") {
                // Ignore standard references to lower false positives
            } else {
                resultBuilder.matchedPatterns.add("SILENT_INSTALL")
            }
        }

        // Anti-Analysis
        if (s.contains("ro.kernel.qemu") ||
            s.contains("ro.product.model") ||
            s.contains("isDebuggerConnected") ||
            s.contains("frida:rpc") ||
            s.contains("xposed.installer")
        ) {
            resultBuilder.matchedPatterns.add("ANTI_ANALYSIS")
            if (s == "isDebuggerConnected" || s.contains("isDebuggerConnected")) {
                resultBuilder.hasOnlyDebuggerConnected = true
            } else {
                resultBuilder.hasOtherAntiAnalysis = true
            }
        }

        // Native Execution / Shell
        if (s.contains("Runtime.getRuntime().exec") ||
            s == "/system/bin/sh" ||
            s == "/system/bin/su" ||
            s == "sh" || s == "su" ||
            s == "su -c"
        ) {
            resultBuilder.matchedPatterns.add("NATIVE_EXECUTION")
        }

        // Telegram Bot API
        if (s.contains("api.telegram.org") ||
            s == "botToken" ||
            s == "bot_token" ||
            s == "botToken2" ||
            (s.contains("/sendMessage") && s.contains("bot"))
        ) {
            resultBuilder.matchedPatterns.add("TELEGRAM_BOT")
        }

        if (runDecoder) {
            Deobfuscator.tryDecryptXorAndBase64(s, resultBuilder) { dec ->
                runStringScannersInternal(dec, resultBuilder, runDecoder = false)
            }
            Deobfuscator.tryDecryptRepeatedXor(s, resultBuilder) { dec ->
                runStringScannersInternal(dec, resultBuilder, runDecoder = false)
            }
        }
    }

    private fun calculateShannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val len = s.length
        val freqs = HashMap<Char, Int>()
        for (char in s) {
            freqs[char] = freqs.getOrDefault(char, 0) + 1
        }
        var entropy = 0.0
        for (count in freqs.values) {
            val p = count.toDouble() / len
            entropy -= p * (Math.log(p) / Math.log(2.0))
        }
        return entropy
    }

    private fun readUleb128(inputStream: InputStream): Int {
        var result = 0
        var shift = 0
        while (true) {
            val b = inputStream.read()
            if (b == -1) break
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) {
                break
            }
            shift += 7
        }
        return result
    }

    private fun readMutf8Bytes(inputStream: InputStream): ByteArray {
        val bos = ByteArrayOutputStream()
        while (true) {
            val b = inputStream.read()
            if (b == -1 || b == 0) break
            bos.write(b)
        }
        return bos.toByteArray()
    }

    private fun decodeMutf8(bytes: ByteArray): String {
        val len = bytes.size
        val chars = CharArray(len)
        var c = 0
        var i = 0
        while (i < len) {
            val b1 = bytes[i].toInt() and 0xFF
            if (b1 < 0x80) {
                chars[c++] = b1.toChar()
                i++
            } else if ((b1 and 0xE0) == 0xC0) {
                if (i + 1 < len) {
                    val b2 = bytes[i + 1].toInt() and 0xFF
                    chars[c++] = (((b1 and 0x1F) shl 6) or (b2 and 0x3F)).toChar()
                    i += 2
                } else {
                    i++
                }
            } else if ((b1 and 0xF0) == 0xE0) {
                if (i + 2 < len) {
                    val b2 = bytes[i + 1].toInt() and 0xFF
                    val b3 = bytes[i + 2].toInt() and 0xFF
                    chars[c++] = (((b1 and 0x0F) shl 12) or ((b2 and 0x3F) shl 6) or (b3 and 0x3F)).toChar()
                    i += 3
                } else {
                    i++
                }
            } else {
                i++
            }
        }
        return String(chars, 0, c)
    }

    private fun readInt(buf: ByteArray, offset: Int): Int {
        if (offset + 3 >= buf.size) return 0
        return (buf[offset].toInt() and 0xFF) or
                ((buf[offset + 1].toInt() and 0xFF) shl 8) or
                ((buf[offset + 2].toInt() and 0xFF) shl 16) or
                ((buf[offset + 3].toInt() and 0xFF) shl 24)
    }

    internal class AnalysisResultBuilder {
        val dangerousPermissions = mutableListOf<String>()
        var highEntropyDetected = false
        var xorObfuscationDetected = false
        var verifiedObfuscatedPayload = false
        var cryptoApiDetected = false
        var hasOnlyDebuggerConnected = false
        var hasOtherAntiAnalysis = false
        val matchedPatterns = mutableSetOf<String>()
        val extractedEvidence = mutableSetOf<String>()

        fun addManifestInfo(info: XmlManifestInfo) {
            println("  [DEBUG] All Parsed Permissions: ${info.permissions}")
            val dangerousList = listOf(
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.INSTALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_CALL_LOG"
            )
            for (perm in info.permissions) {
                if (dangerousList.contains(perm) && !dangerousPermissions.contains(perm)) {
                    dangerousPermissions.add(perm)
                }
            }
            if (info.deviceAdminEnabled) {
                matchedPatterns.add("DEVICE_ADMIN")
            }

            val suspiciousComponentNames = listOf("ReceiveSms", "SendSMS", "SMSReceiver", "SmsReceiver", "NotificationService")
            for (rec in info.receivers) {
                if (suspiciousComponentNames.any { rec.endsWith(it) || rec.contains(".$it") }) {
                    matchedPatterns.add("SUSPICIOUS_COMPONENT")
                }
            }
            for (srv in info.services) {
                if (suspiciousComponentNames.any { srv.endsWith(it) || srv.contains(".$it") }) {
                    matchedPatterns.add("SUSPICIOUS_COMPONENT")
                }
            }
        }

        fun build(): TriageResult {
            var score = 0

            val hasSms = dangerousPermissions.contains("android.permission.RECEIVE_SMS") ||
                    dangerousPermissions.contains("android.permission.SEND_SMS")
            val hasAccessibility = dangerousPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
            val hasInstaller = dangerousPermissions.contains("android.permission.REQUEST_INSTALL_PACKAGES") ||
                    dangerousPermissions.contains("android.permission.INSTALL_PACKAGES")

            if (hasSms || hasAccessibility || hasInstaller) {
                score += 25
            }

            if (matchedPatterns.contains("SILENT_INSTALL")) {
                if (verifiedObfuscatedPayload || hasInstaller || hasAccessibility) {
                    score += 25
                } else {
                    score += 10
                }
            }

            if (matchedPatterns.contains("ANTI_ANALYSIS")) {
                if (hasOnlyDebuggerConnected && !hasOtherAntiAnalysis) {
                    score += 5
                } else {
                    score += 15
                }
            }

            if (matchedPatterns.contains("NATIVE_EXECUTION")) {
                score += 15
            }

            if (highEntropyDetected && cryptoApiDetected) {
                score += 20
            }

            if (xorObfuscationDetected) {
                score += 15
            }

            if (matchedPatterns.contains("TELEGRAM_BOT")) {
                score += 25
            }

            if (hasSms && matchedPatterns.contains("TELEGRAM_BOT")) {
                matchedPatterns.add("SMS_STEALER")
                score += 25
            }

            if (hasInstaller && matchedPatterns.contains("SILENT_INSTALL")) {
                matchedPatterns.add("DROPPER")
                score += 20
            }

            if (matchedPatterns.contains("SUSPICIOUS_COMPONENT")) {
                score += 20
            }

            score = maxOf(0, minOf(100, score))

            val status = when {
                score < 40 -> TriageStatus.SAFE
                score < 75 -> TriageStatus.GREY_AREA
                else -> TriageStatus.MALICIOUS
            }

            return TriageResult(
                score = score,
                status = status,
                dangerousPermissions = dangerousPermissions,
                highEntropyDetected = highEntropyDetected,
                xorObfuscationDetected = xorObfuscationDetected,
                matchedPatterns = matchedPatterns.toList(),
                extractedEvidence = extractedEvidence.toList()
            )
        }
    }
}
