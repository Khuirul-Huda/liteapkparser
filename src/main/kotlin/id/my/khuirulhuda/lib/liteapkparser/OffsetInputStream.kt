package id.my.khuirulhuda.lib.liteapkparser

import java.io.InputStream

internal class OffsetInputStream(private val inner: InputStream) : InputStream() {
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
        val r = inner.read(b, off, len)
        if (r > 0) {
            offset += r
        }
        return r
    }

    override fun close() {
        inner.close()
    }
}

internal fun skipFully(inputStream: InputStream, n: Long) {
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
