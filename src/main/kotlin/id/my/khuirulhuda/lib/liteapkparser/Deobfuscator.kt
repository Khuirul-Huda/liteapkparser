package id.my.khuirulhuda.lib.liteapkparser

internal object Deobfuscator {

    private val INTERESTING_KEYWORDS = listOf(
        "http://", "https://", "pm install", "cmd package", 
        "bin/sh", "bin/su", "DexClassLoader", "frida", "xposed",
        "isDebuggerConnected", "ro.kernel.qemu", "api.telegram.org",
        "botToken", "bot_token", "botToken2", "/sendMessage", "chat_id"
    )

    fun tryDecryptXorAndBase64(
        s: String, 
        onDecrypted: (decryptedStr: String, logMsg: String) -> Unit
    ) {
        val clean = s.trim()
        if (clean.length < 8) return

        val decodedBase64 = Base64Decoder.decode(clean)

        val candidates = mutableListOf<ByteArray>()
        candidates.add(clean.toByteArray(Charsets.UTF_8))
        if (decodedBase64 != null) {
            candidates.add(decodedBase64)
        }

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
                    for (kw in INTERESTING_KEYWORDS) {
                        if (decStr.contains(kw, ignoreCase = true)) {
                            onDecrypted(decStr, "[DECRYPTED LITERAL (1-byte XOR key=$key)] '${decStr.trim()}'")
                            break
                        }
                    }
                }
            }
        }
    }

    fun tryDecryptRepeatedXor(
        s: String,
        onDecrypted: (decryptedStr: String, logMsg: String) -> Unit
    ) {
        val clean = s.trim()
        if (clean.length < 8) return

        val decodedBase64 = Base64Decoder.decode(clean)
        val candidate = decodedBase64 ?: clean.toByteArray(Charsets.UTF_8)

        val commonKeys = listOf("key", "secret", "payload", "token", "bot", "admin", "password")

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
                for (kw in INTERESTING_KEYWORDS) {
                    if (decStr.contains(kw, ignoreCase = true)) {
                        onDecrypted(decStr, "[DECRYPTED LITERAL (repeated XOR key=$keyStr)] '${decStr.trim()}'")
                        break
                    }
                }
            }
        }
    }

    fun tryDecryptAes(
        ciphertextBase64: String,
        keys: List<String>,
        onDecrypted: (decryptedStr: String, logMsg: String) -> Unit
    ) {
        val ciphertextBytes = Base64Decoder.decode(ciphertextBase64.trim()) ?: return
        if (ciphertextBytes.size < 16) return

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
                                if (decStr.length >= 6 && INTERESTING_KEYWORDS.any { decStr.contains(it, ignoreCase = true) }) {
                                    val cleanedStr = decStr.filter { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }.trim()
                                    onDecrypted(decStr, "[DECRYPTED LITERAL (AES/CBC key=$keyStr)] '$cleanedStr'")
                                    return
                                }
                            } catch (e: Exception) {}
                        }
                    } else {
                        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec)
                        val decrypted = cipher.doFinal(ciphertextBytes)
                        val decStr = String(decrypted, Charsets.UTF_8).trim()
                        if (decStr.length >= 6 && INTERESTING_KEYWORDS.any { decStr.contains(it, ignoreCase = true) }) {
                            val cleanedStr = decStr.filter { it.code in 32..126 || it == '\n' || it == '\r' || it == '\t' }.trim()
                            onDecrypted(decStr, "[DECRYPTED LITERAL (AES/ECB key=$keyStr)] '$cleanedStr'")
                            return
                        }
                    }
                } catch (e: Exception) {}
            }
        }
    }

    fun scanShortArrays(
        dexBytes: ByteArray, 
        onDecrypted: (decryptedStr: String, logMsg: String) -> Unit
    ) {
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
                        for (kw in INTERESTING_KEYWORDS) {
                            if (decryptedStr.contains(kw, ignoreCase = true)) {
                                val matches = extractPrintableSubstrings(decryptedStr)
                                for (match in matches) {
                                    if (match.length >= 6) {
                                        onDecrypted(match, "[DECRYPTED SHORT ARRAY STRING (key=$key)] '$match'")
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
        Logger.d("Deobfuscator", "Found $foundPayloads array-data payloads in this DEX")
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
}
