package id.my.khuirulhuda.lib.liteapkparser

import java.io.ByteArrayInputStream

internal object DexParser {

    fun parse(
        dexBytes: ByteArray, 
        onStringFound: (String) -> Unit,
        onXorOpcodeDetected: () -> Unit,
        onAesDecrypted: (decryptedStr: String, logMsg: String) -> Unit,
        onShortArrayDecrypted: (decryptedStr: String, logMsg: String) -> Unit
    ) {
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

        val stringIdsSize = ByteReader.readInt(header, 56)
        val stringIdsOffset = ByteReader.readInt(header, 60)

        if (stringIdsSize <= 0 || stringIdsOffset < 64) {
            return
        }

        // Skip to stringIdsOffset
        val toSkip = stringIdsOffset.toLong() - offsetStream.offset
        if (toSkip > 0) {
            ByteReader.skipFully(offsetStream, toSkip)
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
            stringOffsets[i] = ByteReader.readInt(stringIdsBytes, i * 4)
        }

        // Sort offsets chronologically
        val sortedOffsets = stringOffsets.clone()
        sortedOffsets.sort()

        var nextStringIdx = 0
        val xorDetector = XorOpcodeDetector()

        while (true) {
            val currentOffset = offsetStream.offset

            if (nextStringIdx < sortedOffsets.size && currentOffset == sortedOffsets[nextStringIdx].toLong()) {
                ByteReader.readUleb128(offsetStream)
                val stringBytes = ByteReader.readMutf8Bytes(offsetStream)
                val decodedString = ByteReader.decodeMutf8(stringBytes)

                val trimmed = decodedString.trim()
                if (trimmed.length in listOf(16, 24, 32)) {
                    candidateKeys.add(trimmed)
                }
                if (trimmed.length >= 20 && Base64Decoder.decode(trimmed) != null) {
                    candidateCiphertexts.add(trimmed)
                }

                onStringFound(decodedString)

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
                                    onXorOpcodeDetected()
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
                                onXorOpcodeDetected()
                            }
                        }
                    }
                    break
                }
            }
        }

        Logger.d("DexParser", "keys: ${candidateKeys.size}, ciphertexts: ${candidateCiphertexts.size}")
        if (candidateKeys.isNotEmpty() && candidateCiphertexts.isNotEmpty()) {
            for (ciphertext in candidateCiphertexts) {
                Deobfuscator.tryDecryptAes(ciphertext, candidateKeys) { dec, logMsg ->
                    onAesDecrypted(dec, logMsg)
                }
            }
        }
        Deobfuscator.scanShortArrays(dexBytes) { dec, logMsg ->
            onShortArrayDecrypted(dec, logMsg)
        }
    }
}
