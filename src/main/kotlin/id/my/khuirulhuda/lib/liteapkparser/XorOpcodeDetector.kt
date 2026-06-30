package id.my.khuirulhuda.lib.liteapkparser

internal class XorOpcodeDetector {
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
