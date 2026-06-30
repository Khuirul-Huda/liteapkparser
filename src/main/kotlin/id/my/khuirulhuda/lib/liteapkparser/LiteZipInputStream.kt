package id.my.khuirulhuda.lib.liteapkparser

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.PushbackInputStream
import java.util.zip.Inflater

internal class LiteZipInputStream(rawStream: InputStream) {
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
