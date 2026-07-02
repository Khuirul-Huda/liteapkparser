package id.my.khuirulhuda.lib.liteapkparser

import java.io.InputStream
import java.io.ByteArrayOutputStream

internal object ByteReader {

    fun readInt(buf: ByteArray, offset: Int): Int {
        if (offset + 3 >= buf.size) return 0
        return (buf[offset].toInt() and 0xFF) or
                ((buf[offset + 1].toInt() and 0xFF) shl 8) or
                ((buf[offset + 2].toInt() and 0xFF) shl 16) or
                ((buf[offset + 3].toInt() and 0xFF) shl 24)
    }

    fun readUShort(buf: ByteArray, offset: Int): Int {
        if (offset + 1 >= buf.size) return 0
        return (buf[offset].toInt() and 0xFF) or ((buf[offset + 1].toInt() and 0xFF) shl 8)
    }

    fun readUInt(buf: ByteArray, offset: Int): Long {
        return readInt(buf, offset).toLong() and 0xFFFFFFFFL
    }

    fun readUleb128(inputStream: InputStream): Int {
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

    fun readMutf8Bytes(inputStream: InputStream): ByteArray {
        val bos = ByteArrayOutputStream()
        while (true) {
            val b = inputStream.read()
            if (b == -1 || b == 0) break
            bos.write(b)
        }
        return bos.toByteArray()
    }

    fun decodeMutf8(bytes: ByteArray): String {
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

    fun skipFully(inputStream: InputStream, n: Long) {
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
}
