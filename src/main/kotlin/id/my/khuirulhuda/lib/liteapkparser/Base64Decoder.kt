package id.my.khuirulhuda.lib.liteapkparser

internal object Base64Decoder {
    private const val TBL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun decode(s: String): ByteArray? {
        val len = s.length
        if (len < 8 || len % 4 != 0) return null

        // Fast check: verify all characters belong to the Base64 alphabet.
        // This avoids allocations and index lookups for 99.9% of standard DEX strings.
        for (i in 0 until len) {
            val c = s[i]
            val isValid = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '+' || c == '/' || c == '='
            if (!isValid) return null
        }

        val outLen = (len * 3) / 4 - when {
            s.endsWith("==") -> 2
            s.endsWith("=") -> 1
            else -> 0
        }
        if (outLen <= 0) return null
        val res = ByteArray(outLen)
        var p = 0
        var i = 0
        try {
            while (i < len) {
                val c1 = TBL.indexOf(s[i])
                val c2 = TBL.indexOf(s[i + 1])
                val c3 = if (s[i + 2] == '=') 0 else TBL.indexOf(s[i + 2])
                val c4 = if (s[i + 3] == '=') 0 else TBL.indexOf(s[i + 3])
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
