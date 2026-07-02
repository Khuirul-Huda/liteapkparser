package id.my.khuirulhuda.lib.liteapkparser

internal object Base64Decoder {
    private const val TBL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun decode(s: String): ByteArray? {
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
                val c1 = TBL.indexOf(clean[i])
                val c2 = TBL.indexOf(clean[i + 1])
                val c3 = if (clean[i + 2] == '=') 0 else TBL.indexOf(clean[i + 2])
                val c4 = if (clean[i + 3] == '=') 0 else TBL.indexOf(clean[i + 3])
                if (c1 == -1 || c2 == -1 || c3 == -1 || c4 == -1) return null
                val triple = (c1 shl 18) or (c2 shl 12) or (c3 shl 6) or c4
                if (p < res.size) res[p++] = ((triple shl 8) ushr 24).toByte()
                if (p < res.size) res[p++] = ((triple shl 16) ushr 24).toByte()
                if (p < res.size) res[p++] = ((triple shl 24) ushr 24).toByte()
                i += 4
            }
            return res
        } catch (e: Exception) {
            return null
        }
    }
}
