package id.my.khuirulhuda.lib.liteapkparser

internal object Deobfuscator {

    fun tryDecryptXorAndBase64(
        s: String, 
        resultBuilder: LiteApkParser.AnalysisResultBuilder,
        onDecrypted: (String) -> Unit
    ) {
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
                if (!isBase64 && key == 0) continue

                val decrypted = ByteArray(candidate.size)
                for (i in candidate.indices) {
                    decrypted[i] = (candidate[i].toInt() xor key).toByte()
                }
                
                // Trim trailing and leading control bytes from decrypted array before decoding
                var start = 0
                var end = decrypted.size - 1
                while (start <= end && decrypted[start].toInt() in 0..31) {
                    start++
                }
                while (end >= start && decrypted[end].toInt() in 0..31) {
                    end--
                }
                if (start > end) continue

                val decStr = try {
                    val str = String(decrypted, start, end - start + 1, Charsets.UTF_8)
                    val printableCount = str.count { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }
                    if (printableCount.toDouble() / str.length >= 0.90) {
                        str.filter { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }
                    } else null
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
                            onDecrypted(decStr)
                            break
                        }
                    }
                }
            }
        }
    }

    fun tryDecryptRepeatedXor(
        s: String,
        resultBuilder: LiteApkParser.AnalysisResultBuilder,
        onDecrypted: (String) -> Unit
    ) {
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
                        onDecrypted(decStr)
                        break
                    }
                }
            }
        }
    }

    fun tryDecryptAes(
        ciphertextBase64: String,
        keys: List<String>,
        resultBuilder: LiteApkParser.AnalysisResultBuilder,
        onDecrypted: (String) -> Unit
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
                                    onDecrypted(decStr)
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
                            onDecrypted(decStr)
                            return
                        }
                    }
                } catch (e: Exception) {}
            }
        }
    }

    fun scanShortArrays(
        dexBytes: ByteArray, 
        resultBuilder: LiteApkParser.AnalysisResultBuilder,
        onDecrypted: (String) -> Unit
    ) {
        val interestingKeywords = listOf(
            "api.telegram.org", "botToken", "/sendMessage", "chat_id", "http://", "https://"
        )

        var foundPayloads = 0
        var offset = 0
        while (offset <= dexBytes.size - 8) {
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
                                        onDecrypted(match)
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

    fun decodeBase64Pure(s: String): ByteArray? {
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
}
