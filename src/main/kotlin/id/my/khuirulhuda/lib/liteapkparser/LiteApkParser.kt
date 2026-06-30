package id.my.khuirulhuda.lib.liteapkparser

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.PushbackInputStream
import java.util.zip.Inflater

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
                if (trimmed.length >= 20 && decodeBase64Pure(trimmed) != null) {
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
                tryDecryptAes(ciphertext, candidateKeys, resultBuilder)
            }
        }
        scanShortArrays(dexBytes, resultBuilder)
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
            // Lower false positive: Do not flag standard Android framework references to PathClassLoader
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

        // Telegram Bot API (strict matching to avoid false positives on standard Handler.sendMessage)
        if (s.contains("api.telegram.org") ||
            s == "botToken" ||
            s == "bot_token" ||
            s == "botToken2" ||
            (s.contains("/sendMessage") && s.contains("bot"))
        ) {
            resultBuilder.matchedPatterns.add("TELEGRAM_BOT")
        }

        if (runDecoder) {
            tryDecryptXorAndBase64(s, resultBuilder)
            tryDecryptRepeatedXor(s, resultBuilder)
        }
    }

    private fun tryDecryptXorAndBase64(s: String, resultBuilder: AnalysisResultBuilder) {
        val clean = s.trim()
        if (clean.length < 8) return

        val decodedBase64 = decodeBase64Pure(clean)

        val candidates = mutableListOf<ByteArray>()
        candidates.add(clean.toByteArray(Charsets.UTF_8))
        if (decodedBase64 != null) {
            candidates.add(decodedBase64)
        }

        val interestingKeywords = listOf(
            "http://", "https://", "pm install", "cmd package", 
            "bin/sh", "bin/su", "DexClassLoader", "frida", "xposed",
            "isDebuggerConnected", "ro.kernel.qemu", "api.telegram.org",
            "botToken", "bot_token", "botToken2", "/sendMessage", "chat_id"
        )

        for (candidateIdx in candidates.indices) {
            val candidate = candidates[candidateIdx]
            val isBase64 = (candidateIdx > 0)

            for (key in 0..255) {
                // If not base64 and key is 0, it's just raw plaintext (already scanned), skip it.
                if (!isBase64 && key == 0) continue

                val decrypted = ByteArray(candidate.size)
                for (i in candidate.indices) {
                    decrypted[i] = (candidate[i].toInt() xor key).toByte()
                }
                val decStr = try {
                    val str = String(decrypted, Charsets.UTF_8)
                    if (str.all { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }) str else null
                } catch (e: Exception) {
                    null
                }

                if (decStr != null && decStr.length >= 6) {
                    for (kw in interestingKeywords) {
                        if (decStr.contains(kw, ignoreCase = true)) {
                            println("    [DECRYPTED LITERAL (1-byte XOR key=$key)] '${decStr.trim()}'")
                            resultBuilder.extractedEvidence.add(decStr.trim())
                            resultBuilder.xorObfuscationDetected = true
                            resultBuilder.verifiedObfuscatedPayload = true
                            runStringScannersInternal(decStr, resultBuilder, runDecoder = false)
                            break
                        }
                    }
                }
            }
        }
    }

    private fun tryDecryptRepeatedXor(s: String, resultBuilder: AnalysisResultBuilder) {
        val clean = s.trim()
        if (clean.length < 8) return

        val decodedBase64 = decodeBase64Pure(clean)
        val candidate = decodedBase64 ?: clean.toByteArray(Charsets.UTF_8)

        val commonKeys = listOf("key", "secret", "payload", "token", "bot", "admin", "password")
        val interestingKeywords = listOf(
            "http://", "https://", "pm install", "cmd package", 
            "bin/sh", "bin/su", "DexClassLoader", "api.telegram.org"
        )

        for (keyStr in commonKeys) {
            val keyBytes = keyStr.toByteArray(Charsets.UTF_8)
            val decrypted = ByteArray(candidate.size)
            for (i in candidate.indices) {
                decrypted[i] = (candidate[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            val decStr = try {
                val str = String(decrypted, Charsets.UTF_8)
                if (str.all { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }) str else null
            } catch (e: Exception) {
                null
            }

            if (decStr != null && decStr.length >= 6) {
                for (kw in interestingKeywords) {
                    if (decStr.contains(kw, ignoreCase = true)) {
                        println("    [DECRYPTED LITERAL (repeated XOR key=$keyStr)] '${decStr.trim()}'")
                        resultBuilder.extractedEvidence.add(decStr.trim())
                        resultBuilder.xorObfuscationDetected = true
                        resultBuilder.verifiedObfuscatedPayload = true
                        runStringScannersInternal(decStr, resultBuilder, runDecoder = false)
                    }
                }
            }
        }
    }

    private fun tryDecryptAes(
        ciphertextBase64: String,
        keys: List<String>,
        resultBuilder: AnalysisResultBuilder
    ) {
        val ciphertextBytes = decodeBase64Pure(ciphertextBase64.trim()) ?: return
        if (ciphertextBytes.size < 16) return

        val interestingKeywords = listOf(
            "http://", "https://", "pm install", "cmd package", 
            "bin/sh", "bin/su", "DexClassLoader", "api.telegram.org",
            "botToken", "bot_token", "chat_id", "/sendMessage"
        )

        for (keyStr in keys) {
            val keyBytes = keyStr.toByteArray(Charsets.UTF_8)
            val modes = listOf("AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding")
            for (mode in modes) {
                try {
                    val keySpec = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
                    val cipher = javax.crypto.Cipher.getInstance(mode)
                    
                    if (mode.contains("CBC")) {
                        // Try IV equal to key, or IV equal to all zeros
                        val ivs = listOf(keyBytes.copyOf(16), ByteArray(16))
                        for (iv in ivs) {
                            try {
                                val ivSpec = javax.crypto.spec.IvParameterSpec(iv)
                                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec)
                                val decrypted = cipher.doFinal(ciphertextBytes)
                                val decStr = String(decrypted, Charsets.UTF_8).trim()
                                 if (decStr.length >= 6 && interestingKeywords.any { decStr.contains(it, ignoreCase = true) }) {
                                    val cleanedStr = decStr.filter { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }.trim()
                                    println("    [DECRYPTED LITERAL (AES/CBC key=$keyStr)] '$cleanedStr'")
                                    resultBuilder.extractedEvidence.add(cleanedStr)
                                    resultBuilder.xorObfuscationDetected = true
                                    resultBuilder.verifiedObfuscatedPayload = true
                                    runStringScannersInternal(decStr, resultBuilder, runDecoder = false)
                                    return
                                }
                            } catch (e: Exception) {}
                        }
                    } else {
                        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec)
                        val decrypted = cipher.doFinal(ciphertextBytes)
                        val decStr = String(decrypted, Charsets.UTF_8).trim()
                        if (decStr.length >= 6 && interestingKeywords.any { decStr.contains(it, ignoreCase = true) }) {
                            val cleanedStr = decStr.filter { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }.trim()
                            println("    [DECRYPTED LITERAL (AES/ECB key=$keyStr)] '$cleanedStr'")
                            resultBuilder.extractedEvidence.add(cleanedStr)
                            resultBuilder.xorObfuscationDetected = true
                            resultBuilder.verifiedObfuscatedPayload = true
                            runStringScannersInternal(decStr, resultBuilder, runDecoder = false)
                            return
                        }
                    }
                } catch (e: Exception) {}
            }
        }
    }

    private fun scanShortArrays(dexBytes: ByteArray, resultBuilder: AnalysisResultBuilder) {
        val interestingKeywords = listOf(
            "api.telegram.org", "botToken", "/sendMessage", "chat_id", "http://", "https://"
        )

        var foundPayloads = 0
        var offset = 0
        while (offset <= dexBytes.size - 8) {
            // Match the array-data opcode for 16-bit elements (0x0300 -> 00 03) with element width 2 (0x0002 -> 02 00)
            if (dexBytes[offset] == 0x00.toByte() && dexBytes[offset + 1] == 0x03.toByte() &&
                dexBytes[offset + 2] == 0x02.toByte() && dexBytes[offset + 3] == 0x00.toByte()
            ) {
                foundPayloads++
                val count = (dexBytes[offset + 4].toInt() and 0xFF) or
                            ((dexBytes[offset + 5].toInt() and 0xFF) shl 8) or
                            ((dexBytes[offset + 6].toInt() and 0xFF) shl 16) or
                            ((dexBytes[offset + 7].toInt() and 0xFF) shl 24)

                if (count in 4..4000 && offset + 8 + count * 2 <= dexBytes.size) {
                    val shortArray = IntArray(count)
                    for (i in 0 until count) {
                        val base = offset + 8 + i * 2
                        shortArray[i] = (dexBytes[base].toInt() and 0xFF) or ((dexBytes[base + 1].toInt() and 0xFF) shl 8)
                    }

                    // Brute force 16-bit key
                    for (key in 0..65535) {
                        val chars = CharArray(count)
                        for (i in 0 until count) {
                            chars[i] = (shortArray[i] xor key).toChar()
                        }
                        val decryptedStr = String(chars)
                        for (kw in interestingKeywords) {
                            if (decryptedStr.contains(kw, ignoreCase = true)) {
                                val matches = extractPrintableSubstrings(decryptedStr)
                                for (match in matches) {
                                    if (match.length >= 6) {
                                        println("    [DECRYPTED SHORT ARRAY STRING (key=$key)] '$match'")
                                        resultBuilder.extractedEvidence.add(match)
                                        resultBuilder.xorObfuscationDetected = true
                                        resultBuilder.verifiedObfuscatedPayload = true
                                        runStringScannersInternal(match, resultBuilder, runDecoder = false)
                                    }
                                }
                                break
                            }
                        }
                    }
                }
            }
            offset += 2
        }
        println("  [SHORT ARRAYS] Found $foundPayloads array-data payloads in this DEX")
    }

    private fun extractPrintableSubstrings(s: String): List<String> {
        val list = mutableListOf<String>()
        val current = StringBuilder()
        for (c in s) {
            if (c.code in 32..126 || c == '\n' || c == '\r' || c == '\t') {
                current.append(c)
            } else {
                if (current.length >= 6) {
                    list.add(current.toString().trim())
                }
                current.setLength(0)
            }
        }
        if (current.length >= 6) {
            list.add(current.toString().trim())
        }
        return list
    }

    private fun decodeBase64Pure(s: String): ByteArray? {
        val tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val clean = s.filter { !it.isWhitespace() }
        if (clean.isEmpty() || clean.length % 4 != 0) return null
        val outLen = (clean.length * 3) / 4 - when {
            clean.endsWith("==") -> 2
            clean.endsWith("=") -> 1
            else -> 0
        }
        if (outLen <= 0) return null
        val res = ByteArray(outLen)
        var p = 0
        var i = 0
        try {
            while (i < clean.length) {
                val c1 = tbl.indexOf(clean[i])
                val c2 = tbl.indexOf(clean[i + 1])
                val c3 = if (clean[i + 2] == '=') 0 else tbl.indexOf(clean[i + 2])
                val c4 = if (clean[i + 3] == '=') 0 else tbl.indexOf(clean[i + 3])
                if (c1 == -1 || c2 == -1 || c3 == -1 || c4 == -1) return null
                val triple = (c1 shl 18) or (c2 shl 12) or (c3 shl 6) or c4
                if (p < outLen) res[p++] = ((triple shl 8) ushr 24).toByte()
                if (p < outLen) res[p++] = ((triple shl 16) ushr 24).toByte()
                if (p < outLen) res[p++] = ((triple shl 24) ushr 24).toByte()
                i += 4
            }
            return res
        } catch (e: Exception) {
            return null
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

    private fun skipFully(inputStream: InputStream, n: Long) {
        var remaining = n
        val buffer = ByteArray(8192)
        while (remaining > 0) {
            val skipped = inputStream.skip(remaining)
            if (skipped <= 0) {
                val toRead = minOf(remaining, buffer.size.toLong()).toInt()
                val read = inputStream.read(buffer, 0, toRead)
                if (read <= 0) break
                remaining -= read
            } else {
                remaining -= skipped
            }
        }
    }

    private fun readInt(buf: ByteArray, offset: Int): Int {
        if (offset + 3 >= buf.size) return 0
        return (buf[offset].toInt() and 0xFF) or
                ((buf[offset + 1].toInt() and 0xFF) shl 8) or
                ((buf[offset + 2].toInt() and 0xFF) shl 16) or
                ((buf[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readUShort(buf: ByteArray, offset: Int): Int {
        if (offset + 1 >= buf.size) return 0
        return (buf[offset].toInt() and 0xFF) or ((buf[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun readUInt(buf: ByteArray, offset: Int): Long {
        return readInt(buf, offset).toLong() and 0xFFFFFFFFL
    }

    private class OffsetInputStream(private val inner: InputStream) : InputStream() {
        var offset = 0L
            private set

        override fun read(): Int {
            val b = inner.read()
            if (b != -1) {
                offset++
            }
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val read = inner.read(b, off, len)
            if (read > 0) {
                offset += read
            }
            return read
        }

        override fun skip(n: Long): Long {
            val skipped = inner.skip(n)
            if (skipped > 0) {
                offset += skipped
            }
            return skipped
        }
    }

    private class XorOpcodeDetector {
        private val history = IntArray(32)
        private var head = 0
        private var count = 0

        private val isBranchOpcode = BooleanArray(256).apply {
            val branchOpcodes = setOf(0x28, 0x29, 0x2a, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d)
            for (op in branchOpcodes) {
                this[op] = true
            }
        }

        fun feed(b: Int): Boolean {
            history[head] = b
            head = (head + 1) and 31
            if (count < 32) count++

            if (count == 32) {
                var index48 = -1
                var indexXor = -1
                var index4c = -1
                var hasLoopBranch = false

                for (i in 0 until 32) {
                    val idx = (head + i) and 31
                    val valAt = history[idx]
                    if (valAt == 0x48) {
                        index48 = i
                    } else if (index48 != -1 && (valAt == 0xeb || valAt == 0xf9 || valAt == 0xdb || valAt == 0xd3 || valAt == 0xec)) {
                        indexXor = i
                    } else if (indexXor != -1 && valAt == 0x4c) {
                        index4c = i
                    }
                    if (valAt in 0..255 && isBranchOpcode[valAt]) {
                        hasLoopBranch = true
                    }
                }
                if (index48 != -1 && indexXor != -1 && index4c != -1 && index48 < indexXor && indexXor < index4c && hasLoopBranch) {
                    return true
                }
            }
            return false
        }
    }

    private class LiteZipInputStream(rawStream: InputStream) {
        private val inputStream = PushbackInputStream(rawStream, 8192)
        private val buffer = ByteArray(8192)

        data class ZipEntry(
            val name: String,
            val compressionMethod: Int,
            val compressedSize: Long,
            val uncompressedSize: Long,
            val gpFlag: Int
        )

        fun nextEntry(): ZipEntry? {
            val sigBytes = ByteArray(4)
            if (!readFully(sigBytes)) return null
            val sig = readInt(sigBytes, 0)
            if (sig != 0x04034b50) {
                return null
            }
            val header = ByteArray(26)
            if (!readFully(header)) return null
            val gpFlag = readUShort(header, 2)
            val compressionMethod = readUShort(header, 4)
            val compressedSize = readUInt(header, 14)
            val uncompressedSize = readUInt(header, 18)
            val fileNameLen = readUShort(header, 22)
            val extraFieldLen = readUShort(header, 24)

            val fileNameBytes = ByteArray(fileNameLen)
            if (!readFully(fileNameBytes)) return null
            val fileName = String(fileNameBytes, Charsets.UTF_8)

            skipFully(extraFieldLen.toLong())

            return ZipEntry(fileName, compressionMethod, compressedSize, uncompressedSize, gpFlag)
        }

        fun readEntryData(entry: ZipEntry): ByteArray? {
            return processEntryData(entry, keepData = true)
        }

        fun skipEntryData(entry: ZipEntry) {
            processEntryData(entry, keepData = false)
        }

        private fun processEntryData(entry: ZipEntry, keepData: Boolean): ByteArray? {
            val out = if (keepData) ByteArrayOutputStream() else null
            val isCompressed = entry.compressionMethod == 8

            if (!isCompressed) {
                var remaining = entry.uncompressedSize
                val buf = ByteArray(8192)
                while (remaining > 0) {
                    val toRead = minOf(remaining, buf.size.toLong()).toInt()
                    val read = inputStream.read(buf, 0, toRead)
                    if (read <= 0) break
                    if (keepData) {
                        out?.write(buf, 0, read)
                    }
                    remaining -= read
                }
            } else {
                val decompressor = Inflater(true)
                val buf = ByteArray(8192)
                val outBuf = ByteArray(8192)
                try {
                    val hasSize = (entry.gpFlag and 0x08) == 0
                    var compressedBytesRead = 0L

                    while (!decompressor.finished()) {
                        var lastReadSize = 0
                        if (decompressor.needsInput()) {
                            val toRead = if (hasSize) {
                                minOf(buf.size.toLong(), entry.compressedSize - compressedBytesRead).toInt()
                            } else {
                                buf.size
                            }
                            if (toRead <= 0 && hasSize) {
                                break
                            }
                            val read = inputStream.read(buf, 0, toRead)
                            if (read <= 0) break
                            lastReadSize = read
                            decompressor.setInput(buf, 0, read)
                            compressedBytesRead += read
                        }

                        while (!decompressor.needsInput() && !decompressor.finished()) {
                            val count = decompressor.inflate(outBuf)
                            if (count > 0 && keepData) {
                                out?.write(outBuf, 0, count)
                            }
                        }

                        if (decompressor.finished() && lastReadSize > 0) {
                            val remainingInput = decompressor.remaining
                            if (remainingInput > 0) {
                                inputStream.unread(buf, lastReadSize - remainingInput, remainingInput)
                            }
                        }
                    }
                } finally {
                    decompressor.end()
                }

                if ((entry.gpFlag and 0x08) != 0) {
                    val descSig = ByteArray(4)
                    if (readFully(descSig)) {
                        val sig = readInt(descSig, 0)
                        if (sig == 0x08074b50) {
                            skipFully(12)
                        } else {
                            skipFully(8)
                        }
                    }
                }
            }
            return out?.toByteArray()
        }

        private fun readFully(b: ByteArray): Boolean {
            var total = 0
            while (total < b.size) {
                val count = inputStream.read(b, total, b.size - total)
                if (count <= 0) return false
                total += count
            }
            return true
        }

        private fun skipFully(n: Long) {
            var remaining = n
            while (remaining > 0) {
                val skipped = inputStream.skip(remaining)
                if (skipped <= 0) {
                    val toRead = minOf(remaining, buffer.size.toLong()).toInt()
                    val read = inputStream.read(buffer, 0, toRead)
                    if (read <= 0) break
                    remaining -= read
                } else {
                    remaining -= skipped
                }
            }
        }

        private fun readInt(buf: ByteArray, offset: Int): Int {
            if (offset + 3 >= buf.size) return 0
            return (buf[offset].toInt() and 0xFF) or
                    ((buf[offset + 1].toInt() and 0xFF) shl 8) or
                    ((buf[offset + 2].toInt() and 0xFF) shl 16) or
                    ((buf[offset + 3].toInt() and 0xFF) shl 24)
        }

        private fun readUShort(buf: ByteArray, offset: Int): Int {
            if (offset + 1 >= buf.size) return 0
            return (buf[offset].toInt() and 0xFF) or ((buf[offset + 1].toInt() and 0xFF) shl 8)
        }

        private fun readUInt(buf: ByteArray, offset: Int): Long {
            return readInt(buf, offset).toLong() and 0xFFFFFFFFL
        }
    }

    private class BinaryXmlParser(private val data: ByteArray) {
        private var offset = 0
        private val stringPool = ArrayList<String>()

        fun parse(): XmlManifestInfo {
            if (data.size < 8) return XmlManifestInfo(emptyList(), false, emptyList(), emptyList())
            val magic = readInt(0)
            println("  [DEBUG XML MAGIC] magic = ${String.format("0x%08X", magic)}")
            if (magic != 0x00080003) {
                return XmlManifestInfo(emptyList(), false, emptyList(), emptyList())
            }
            val fileSize = readInt(4)
            offset = 8

            val permissions = mutableListOf<String>()
            var deviceAdminEnabled = false
            var currentComponentClass: String? = null
            val receivers = mutableListOf<String>()
            val services = mutableListOf<String>()

            while (offset < data.size && offset < fileSize) {
                val chunkType = readInt(offset)
                val chunkSize = readInt(offset + 4)
                if (chunkSize <= 0) break

                val type = chunkType and 0xFFFF
                when (type) {
                    0x0001 -> { // RES_STRING_POOL_TYPE
                        parseStringPool(offset)
                    }
                    0x0102 -> { // RES_XML_START_ELEMENT_TYPE
                        val nameIdx = readInt(offset + 20)
                        val tagName = getString(nameIdx)

                        val headerSize = readShort(offset + 2) and 0xFFFF
                        val attrStart = readShort(offset + 24) and 0xFFFF
                        val attrSize = readShort(offset + 26) and 0xFFFF
                        val attrCount = readShort(offset + 28) and 0xFFFF
                        var attrOffset = offset + headerSize + attrStart

                        var attrNameValue: String? = null

                        for (i in 0 until attrCount) {
                            readInt(attrOffset) // Namespace index (unused)
                            val attrNameIdx = readInt(attrOffset + 4)
                            val attrName = getString(attrNameIdx)
                            val rawValueIdx = readInt(attrOffset + 8)
                            val typedValueType = data[attrOffset + 15].toInt() and 0xFF
                            val typedValueData = readInt(attrOffset + 16)

                            val attrVal = if (rawValueIdx != -1) {
                                getString(rawValueIdx)
                            } else if (typedValueType == 3) { // TYPE_STRING
                                getString(typedValueData)
                            } else {
                                ""
                            }

                            if (attrName == "name") {
                                attrNameValue = attrVal
                            }
                            attrOffset += attrSize
                        }

                        if (tagName == "uses-permission" && attrNameValue != null) {
                            permissions.add(attrNameValue)
                        } else if (tagName == "receiver" && attrNameValue != null) {
                            receivers.add(attrNameValue)
                            currentComponentClass = attrNameValue
                        } else if (tagName == "service" && attrNameValue != null) {
                            services.add(attrNameValue)
                            currentComponentClass = attrNameValue
                        } else if (tagName == "action" && attrNameValue == "android.app.action.DEVICE_ADMIN_ENABLED") {
                            if (currentComponentClass != null && receivers.contains(currentComponentClass)) {
                                deviceAdminEnabled = true
                            }
                        }
                    }
                    0x0103 -> { // RES_XML_END_ELEMENT_TYPE
                        val nameIdx = readInt(offset + 20)
                        val tagName = getString(nameIdx)
                        if (tagName == "receiver" || tagName == "service") {
                            currentComponentClass = null
                        }
                    }
                }
                offset += chunkSize
            }

            return XmlManifestInfo(permissions, deviceAdminEnabled, receivers, services)
        }

        private fun parseStringPool(startOffset: Int) {
            val stringCount = readInt(startOffset + 8)
            val flags = readInt(startOffset + 16)
            val stringStart = readInt(startOffset + 20)

            val isUtf8 = (flags and 0x00000100) != 0

            val offsets = IntArray(stringCount)
            for (i in 0 until stringCount) {
                offsets[i] = readInt(startOffset + 28 + i * 4)
            }

            val dataStart = startOffset + stringStart
            for (i in 0 until stringCount) {
                val strOffset = dataStart + offsets[i]
                if (strOffset >= data.size) {
                    stringPool.add("")
                    continue
                }
                if (isUtf8) {
                    var p = strOffset
                    val utf16Len = readUtf8Len(p)
                    p += utf16Len.bytesRead
                    val utf8Len = readUtf8Len(p)
                    p += utf8Len.bytesRead

                    val len = utf8Len.value
                    if (p + len <= data.size) {
                        stringPool.add(String(data, p, len, Charsets.UTF_8))
                    } else {
                        stringPool.add("")
                    }
                } else {
                    var p = strOffset
                    val utf16Len = readUtf16Len(p)
                    p += utf16Len.bytesRead
                    val len = utf16Len.value * 2
                    if (p + len <= data.size) {
                        stringPool.add(decodeUtf16String(p, len))
                    } else {
                        stringPool.add("")
                    }
                }
            }
        }

        private class LengthResult(val value: Int, val bytesRead: Int)

        private fun readUtf8Len(offset: Int): LengthResult {
            val b1 = data[offset].toInt() and 0xFF
            return if ((b1 and 0x80) != 0) {
                val b2 = data[offset + 1].toInt() and 0xFF
                LengthResult(((b1 and 0x7F) shl 8) or b2, 2)
            } else {
                LengthResult(b1, 1)
            }
        }

        private fun readUtf16Len(offset: Int): LengthResult {
            val w1 = readShort(offset)
            return if ((w1 and 0x8000) != 0) {
                val w2 = readShort(offset + 2)
                LengthResult(((w1 and 0x7FFF) shl 16) or w2, 4)
            } else {
                LengthResult(w1, 2)
            }
        }

        private fun decodeUtf16String(start: Int, byteCount: Int): String {
            val chars = CharArray(byteCount / 2)
            for (i in chars.indices) {
                chars[i] = readShort(start + i * 2).toChar()
            }
            val len = if (chars.isNotEmpty() && chars.last() == '\u0000') chars.size - 1 else chars.size
            return String(chars, 0, len)
        }

        private fun readInt(off: Int): Int {
            if (off + 3 >= data.size) return 0
            return (data[off].toInt() and 0xFF) or
                    ((data[off + 1].toInt() and 0xFF) shl 8) or
                    ((data[off + 2].toInt() and 0xFF) shl 16) or
                    ((data[off + 3].toInt() and 0xFF) shl 24)
        }

        private fun readShort(off: Int): Int {
            if (off + 1 >= data.size) return 0
            return (data[off].toInt() and 0xFF) or ((data[off + 1].toInt() and 0xFF) shl 8)
        }

        private fun getString(index: Int): String {
            if (index >= 0 && index < stringPool.size) {
                return stringPool[index]
            }
            return ""
        }
    }

    private data class XmlManifestInfo(
        val permissions: List<String>,
        val deviceAdminEnabled: Boolean,
        val receivers: List<String>,
        val services: List<String>
    )

    private class AnalysisResultBuilder {
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

            // Check for known malicious receiver and service class suffixes
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

            // SMS / Accessibility + Installer Permission Abuse
            if (hasSms || hasAccessibility || hasInstaller) {
                score += 25
            }

            // Silent Install / Dynamic Code Loading Patterns found
            if (matchedPatterns.contains("SILENT_INSTALL")) {
                if (verifiedObfuscatedPayload || hasInstaller || hasAccessibility) {
                    score += 25
                } else {
                    score += 10 // Lower points for unverified patterns in benign contexts
                }
            }

            // Anti-Analysis / Debugger Evasion Patterns found
            if (matchedPatterns.contains("ANTI_ANALYSIS")) {
                if (hasOnlyDebuggerConnected && !hasOtherAntiAnalysis) {
                    score += 5 // Lowered points for just checking if debugger is connected
                } else {
                    score += 15
                }
            }

            // Native Shell / Command Execution found
            if (matchedPatterns.contains("NATIVE_EXECUTION")) {
                score += 15
            }

            // High Shannon Entropy + Cryptographic Imports
            if (highEntropyDetected && cryptoApiDetected) {
                score += 20
            }

            // XOR decryption loop pattern detected
            if (xorObfuscationDetected) {
                score += 15
            }

            // Telegram Bot API patterns found
            if (matchedPatterns.contains("TELEGRAM_BOT")) {
                score += 25
            }

            // SMS Stealer / RCE Bot logic: SMS permissions + Telegram bot patterns
            if (hasSms && matchedPatterns.contains("TELEGRAM_BOT")) {
                matchedPatterns.add("SMS_STEALER")
                score += 25
            }

            // Dropper logic: Installer permissions + Silent install patterns
            if (hasInstaller && matchedPatterns.contains("SILENT_INSTALL")) {
                matchedPatterns.add("DROPPER")
                score += 20
            }

            // Suspicious component names matching known malware patterns (e.g. ReceiveSms, NotificationService)
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
