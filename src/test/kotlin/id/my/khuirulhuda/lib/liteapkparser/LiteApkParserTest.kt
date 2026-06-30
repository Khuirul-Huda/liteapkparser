package id.my.khuirulhuda.lib.liteapkparser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Method

class LiteApkParserTest {

    @Test
    fun testAnalyzeApkReal() {
        val apkFile = File("test.apk")
        if (apkFile.exists()) {
            val parser = LiteApkParser()
            val result = parser.analyzeApk(apkFile)
            println("Real Malware APK Triage Result:")
            println("Score: ${result.score}")
            println("Status: ${result.status}")
            println("Dangerous Permissions: ${result.dangerousPermissions}")
            println("High Entropy Detected: ${result.highEntropyDetected}")
            println("XOR Obfuscation Detected: ${result.xorObfuscationDetected}")
            println("Matched Patterns: ${result.matchedPatterns}")
            assertNotNull(result)
        } else {
            println("APK file not found at ${apkFile.absolutePath}, skipping test.")
        }
    }

    @Test
    fun testShannonEntropy() {
        val parser = LiteApkParser()
        val method = LiteApkParser::class.java.getDeclaredMethod("calculateShannonEntropy", String::class.java).apply {
            isAccessible = true
        }

        val entropyFlat = method.invoke(parser, "AAAAAA") as Double
        assertEquals(0.0, entropyFlat, 0.001)

        val entropySeq = method.invoke(parser, "ABCDEF") as Double
        // H(X) = -6 * (1/6 * log2(1/6)) = log2(6) = 2.58496
        assertEquals(2.585, entropySeq, 0.001)

        // Random-like string with high entropy
        val entropyHigh = method.invoke(parser, "q7a9vB#zP!wX9\$dM2@sK") as Double
        assertTrue(entropyHigh > 4.0)
    }

    @Test
    fun testXorOpcodeDetector() {
        val detectorClass = LiteApkParser::class.java.declaredClasses.first { it.simpleName == "XorOpcodeDetector" }
        val detector = detectorClass.getDeclaredConstructor().newInstance()
        val feedMethod = detectorClass.getMethod("feed", Int::class.java)

        // Pattern: 0x48 (aget-byte), then 0xeb (xor-int/2addr), then 0x4c (aput-byte)
        // Feed unrelated bytes
        for (i in 0..30) {
            val detected = feedMethod.invoke(detector, 0x00) as Boolean
            assertFalse(detected)
        }

        // Feed pattern
        assertFalse(feedMethod.invoke(detector, 0x48) as Boolean) // aget-byte
        assertFalse(feedMethod.invoke(detector, 0x01) as Boolean)
        assertFalse(feedMethod.invoke(detector, 0xeb) as Boolean) // xor
        assertFalse(feedMethod.invoke(detector, 0x02) as Boolean)
        assertFalse(feedMethod.invoke(detector, 0x28) as Boolean) // loop branch (goto)
        
        // Final trigger on aput-byte
        val detected = feedMethod.invoke(detector, 0x4c) as Boolean // aput-byte
        assertTrue(detected)
    }

    @Test
    fun testMutf8Decoding() {
        val parser = LiteApkParser()
        val method = LiteApkParser::class.java.getDeclaredMethod("decodeMutf8", ByteArray::class.java).apply {
            isAccessible = true
        }

        // ASCII string
        val asciiBytes = "Hello".toByteArray(Charsets.UTF_8)
        val decodedAscii = method.invoke(parser, asciiBytes) as String
        assertEquals("Hello", decodedAscii)

        // UTF-8 multi-byte characters
        val multiByte = "tasbih".toByteArray(Charsets.UTF_8)
        val decodedMulti = method.invoke(parser, multiByte) as String
        assertEquals("tasbih", decodedMulti)
    }

    @Test
    fun testXorAndBase64Decryption() {
        val parser = LiteApkParser()
        
        // 1. Prepare target string: "http://malicious-url.com"
        val target = "http://malicious-url.com"
        val key = 0x5A
        val encrypted = target.toByteArray(Charsets.UTF_8).map { (it.toInt() xor key).toByte() }.toByteArray()
        
        // Base64 encode pure
        val tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val sb = java.lang.StringBuilder()
        var i = 0
        while (i < encrypted.size) {
            val b1 = encrypted[i].toInt() and 0xFF
            val b2 = if (i + 1 < encrypted.size) encrypted[i + 1].toInt() and 0xFF else -1
            val b3 = if (i + 2 < encrypted.size) encrypted[i + 2].toInt() and 0xFF else -1
            val triple = (b1 shl 16) or ((if (b2 != -1) b2 else 0) shl 8) or (if (b3 != -1) b3 else 0)
            sb.append(tbl[(triple ushr 18) and 0x3F])
            sb.append(tbl[(triple ushr 12) and 0x3F])
            sb.append(if (b2 != -1) tbl[(triple ushr 6) and 0x3F] else '=')
            sb.append(if (b3 != -1) tbl[triple and 0x3F] else '=')
            i += 3
        }
        val base64EncodedXored = sb.toString()
        
        // 2. Setup AnalysisResultBuilder
        val builderClass = LiteApkParser::class.java.declaredClasses.first { it.simpleName == "AnalysisResultBuilder" }
        val builder = builderClass.getDeclaredConstructor().newInstance()
        
        // 3. Invoke tryDecryptXorAndBase64
        val decryptMethod = LiteApkParser::class.java.getDeclaredMethod("tryDecryptXorAndBase64", String::class.java, builderClass).apply {
            isAccessible = true
        }
        
        decryptMethod.invoke(parser, base64EncodedXored, builder)
        
        // 4. Verify detection
        val xorObfuscationDetectedField = builderClass.getDeclaredField("xorObfuscationDetected").apply { isAccessible = true }
        val verifiedObfuscatedPayloadField = builderClass.getDeclaredField("verifiedObfuscatedPayload").apply { isAccessible = true }
        
        assertTrue(xorObfuscationDetectedField.get(builder) as Boolean)
        assertTrue(verifiedObfuscatedPayloadField.get(builder) as Boolean)
    }
}

