package id.my.khuirulhuda.lib.liteapkparser

internal data class XmlManifestInfo(
    val permissions: List<String>,
    val deviceAdminEnabled: Boolean,
    val receivers: List<String>,
    val services: List<String>
)

internal class BinaryXmlParser(private val data: ByteArray) {
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

                    val headerSize = readShort(offset + 2).toInt() and 0xFFFF
                    val attrStart = readShort(offset + 24).toInt() and 0xFFFF
                    val attrSize = readShort(offset + 26).toInt() and 0xFFFF
                    val attrCount = readShort(offset + 28).toInt() and 0xFFFF
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

        var offsetsOffset = startOffset + 28
        val offsets = IntArray(stringCount)
        for (i in 0 until stringCount) {
            offsets[i] = readInt(offsetsOffset)
            offsetsOffset += 4
        }

        val baseStringData = startOffset + stringStart
        for (i in 0 until stringCount) {
            val strOffset = baseStringData + offsets[i]
            if (isUtf8) {
                // UTF-8 string layout
                var uOffset = strOffset
                val lengthResult1 = readUtf8Length(uOffset)
                uOffset += lengthResult1.bytesRead
                val lengthResult2 = readUtf8Length(uOffset)
                uOffset += lengthResult2.bytesRead
                val uLen = lengthResult2.value
                if (uLen <= 0) {
                    stringPool.add("")
                } else {
                    val strBytes = ByteArray(uLen)
                    System.arraycopy(data, uOffset, strBytes, 0, uLen)
                    stringPool.add(String(strBytes, Charsets.UTF_8))
                }
            } else {
                // UTF-16 string layout
                var uOffset = strOffset
                val lengthResult = readUtf16Length(uOffset)
                uOffset += lengthResult.bytesRead
                val uLen = lengthResult.value
                if (uLen <= 0) {
                    stringPool.add("")
                } else {
                    val strBytes = ByteArray(uLen * 2)
                    System.arraycopy(data, uOffset, strBytes, 0, uLen * 2)
                    stringPool.add(String(strBytes, Charsets.UTF_16LE))
                }
            }
        }
    }

    private fun readUtf8Length(offset: Int): LengthResult {
        val val1 = data[offset].toInt() and 0xFF
        return if ((val1 and 0x80) != 0) {
            val val2 = data[offset + 1].toInt() and 0xFF
            LengthResult(((val1 and 0x7F) shl 8) or val2, 2)
        } else {
            LengthResult(val1, 1)
        }
    }

    private fun readUtf16Length(offset: Int): LengthResult {
        val val1 = readShort(offset).toInt() and 0xFFFF
        return if ((val1 and 0x8000) != 0) {
            val val2 = readShort(offset + 2).toInt() and 0xFFFF
            LengthResult(((val1 and 0x7FFF) shl 16) or val2, 4)
        } else {
            LengthResult(val1, 2)
        }
    }

    private class LengthResult(val value: Int, val bytesRead: Int)

    private fun readInt(offset: Int): Int {
        if (offset + 3 >= data.size) return 0
        return (data[offset].toInt() and 0xFF) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or
                ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readShort(offset: Int): Short {
        if (offset + 1 >= data.size) return 0
        val res = (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)
        return res.toShort()
    }

    private fun getString(index: Int): String {
        if (index in 0 until stringPool.size) {
            return stringPool[index]
        }
        return ""
    }
}
