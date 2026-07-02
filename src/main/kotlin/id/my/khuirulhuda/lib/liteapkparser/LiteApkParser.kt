package id.my.khuirulhuda.lib.liteapkparser

import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.util.HashMap

class LiteApkParser {

    data class TriageResult(
        val score: Int,
        val status: TriageStatus,
        val dangerousPermissions: List<String>,
        val highEntropyDetected: Boolean,
        val xorObfuscationDetected: Boolean,
        val matchedPatterns: List<String>,
        val extractedEvidence: List<String>
    )

    enum class TriageStatus { SAFE, GREY_AREA, MALICIOUS }

    fun analyzeApk(file: File): TriageResult {
        return file.inputStream().use { inputStream ->
            analyzeApkStream(inputStream)
        }
    }

    fun analyzeApkStream(inputStream: InputStream): TriageResult {
        val zipStream = LiteZipInputStream(inputStream)
        val resultBuilder = AnalysisResultBuilder()

        try {
            while (true) {
                val entry = zipStream.nextEntry() ?: break
                val name = entry.name
                if (name == "AndroidManifest.xml") {
                    val data = zipStream.readEntryData(entry)
                    if (data != null) {
                        try {
                            val manifestInfo = BinaryXmlParser(data).parse()
                            resultBuilder.addManifestInfo(manifestInfo)
                        } catch (e: Exception) {
                            Logger.e("LiteApkParser", "Failed to parse Manifest XML", e)
                        }
                    }
                } else if (name.startsWith("classes") && name.endsWith(".dex")) {
                    val data = zipStream.readEntryData(entry)
                    if (data != null) {
                        try {
                            scanDexBytes(data, resultBuilder)
                        } catch (e: Exception) {
                            Logger.e("LiteApkParser", "Failed to parse DEX", e)
                        }
                    }
                } else {
                    zipStream.skipEntryData(entry)
                }
            }
        } catch (e: Exception) {
            Logger.e("LiteApkParser", "Error reading APK stream", e)
        }

        return resultBuilder.build()
    }

    private fun scanDexBytes(dexBytes: ByteArray, resultBuilder: AnalysisResultBuilder) {
        DexParser.parse(
            dexBytes = dexBytes,
            onStringFound = { s ->
                resultBuilder.strings.add(s)
                runStringScanners(s, resultBuilder)
            },
            onXorOpcodeDetected = {
                resultBuilder.xorObfuscationDetected = true
            },
            onAesDecrypted = { dec, logMsg ->
                Logger.d("LiteApkParser", logMsg)
                resultBuilder.extractedEvidence.add(dec)
                resultBuilder.xorObfuscationDetected = true
                resultBuilder.verifiedObfuscatedPayload = true
                resultBuilder.decryptedStrings.add(dec)
                runStringScannersInternal(dec, resultBuilder, runDecoder = false)
            },
            onShortArrayDecrypted = { dec, logMsg ->
                Logger.d("LiteApkParser", logMsg)
                resultBuilder.extractedEvidence.add(dec)
                resultBuilder.xorObfuscationDetected = true
                resultBuilder.verifiedObfuscatedPayload = true
                resultBuilder.decryptedStrings.add(dec)
                runStringScannersInternal(dec, resultBuilder, runDecoder = false)
            }
        )
    }

    private fun runStringScanners(s: String, resultBuilder: AnalysisResultBuilder) {
        runStringScannersInternal(s, resultBuilder, runDecoder = true)
    }

    private fun runStringScannersInternal(s: String, resultBuilder: AnalysisResultBuilder, runDecoder: Boolean) {
        if (s.contains("javax/crypto/Cipher") ||
            s.contains("javax/crypto/spec/SecretKeySpec") ||
            s.contains("android/util/Base64")
        ) {
            resultBuilder.cryptoApiDetected = true
        }

        if (s.length >= 8) {
            val entropy = calculateShannonEntropy(s)
            if (entropy > 6.5) {
                resultBuilder.highEntropyDetected = true
            }
        }

        // Silent Install / Dropper
        if (s.contains("pm install") ||
            s.contains("cmd package install") ||
            s.contains("application/vnd.android.package-archive") ||
            s.contains("PackageInstaller\$Session") ||
            s.contains("DexClassLoader") ||
            s.contains("PathClassLoader")
        ) {
            if (s == "Ldalvik/system/PathClassLoader;" || s == "dalvik.system.PathClassLoader") {
                // Ignore standard references to lower false positives
            } else {
                resultBuilder.matchedPatterns.add("SILENT_INSTALL")
            }
        }

        // Anti-Analysis
        if (s.contains("ro.kernel.qemu") ||
            s.contains("ro.product.model") ||
            s.contains("isDebuggerConnected") ||
            s.contains("frida:rpc") ||
            s.contains("xposed.installer")
        ) {
            resultBuilder.matchedPatterns.add("ANTI_ANALYSIS")
            if (s == "isDebuggerConnected" || s.contains("isDebuggerConnected")) {
                resultBuilder.hasOnlyDebuggerConnected = true
            } else {
                resultBuilder.hasOtherAntiAnalysis = true
            }
        }

        // Native Execution / Shell
        if (s.contains("Runtime.getRuntime().exec") ||
            s == "/system/bin/sh" ||
            s == "/system/bin/su" ||
            s == "sh" || s == "su" ||
            s == "su -c"
        ) {
            resultBuilder.matchedPatterns.add("NATIVE_EXECUTION")
        }

        // Telegram Bot API
        if (s.contains("api.telegram.org") ||
            s == "botToken" ||
            s == "bot_token" ||
            s == "botToken2" ||
            (s.contains("/sendMessage") && s.contains("bot"))
        ) {
            resultBuilder.matchedPatterns.add("TELEGRAM_BOT")
        }

        if (runDecoder) {
            Deobfuscator.tryDecryptXorAndBase64(s) { dec, logMsg ->
                Logger.d("LiteApkParser", logMsg)
                resultBuilder.extractedEvidence.add(dec)
                resultBuilder.xorObfuscationDetected = true
                resultBuilder.verifiedObfuscatedPayload = true
                resultBuilder.decryptedStrings.add(dec)
                runStringScannersInternal(dec, resultBuilder, runDecoder = false)
            }
            Deobfuscator.tryDecryptRepeatedXor(s) { dec, logMsg ->
                Logger.d("LiteApkParser", logMsg)
                resultBuilder.extractedEvidence.add(dec)
                resultBuilder.xorObfuscationDetected = true
                resultBuilder.verifiedObfuscatedPayload = true
                resultBuilder.decryptedStrings.add(dec)
                runStringScannersInternal(dec, resultBuilder, runDecoder = false)
            }
        }
    }

    private fun calculateShannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val len = s.length
        val freqs = HashMap<Char, Int>()
        for (char in s) {
            freqs[char] = freqs.getOrDefault(char, 0) + 1
        }
        var entropy = 0.0
        for (count in freqs.values) {
            val p = count.toDouble() / len
            entropy -= p * (Math.log(p) / Math.log(2.0))
        }
        return entropy
    }

    internal class AnalysisResultBuilder {
        val dangerousPermissions = mutableListOf<String>()
        var highEntropyDetected = false
        var xorObfuscationDetected = false
        var verifiedObfuscatedPayload = false
        var cryptoApiDetected = false
        var hasOnlyDebuggerConnected = false
        var hasOtherAntiAnalysis = false
        val matchedPatterns = mutableSetOf<String>()
        val extractedEvidence = mutableSetOf<String>()
        val strings = mutableSetOf<String>()
        val decryptedStrings = mutableSetOf<String>()
        var deviceAdminEnabled = false
        val receivers = mutableListOf<String>()
        val services = mutableListOf<String>()

        fun addManifestInfo(info: XmlManifestInfo) {
            Logger.d("LiteApkParser", "All Parsed Permissions: ${info.permissions}")
            val dangerousList = listOf(
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.INSTALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_CALL_LOG"
            )
            for (perm in info.permissions) {
                if (dangerousList.contains(perm) && !dangerousPermissions.contains(perm)) {
                    dangerousPermissions.add(perm)
                }
            }
            if (info.deviceAdminEnabled) {
                deviceAdminEnabled = true
            }
            receivers.addAll(info.receivers)
            services.addAll(info.services)
        }

        fun build(): TriageResult {
            val state = ScanningState(
                permissions = dangerousPermissions,
                strings = strings,
                decrypted = decryptedStrings,
                highEntropyDetected = highEntropyDetected,
                xorObfuscationDetected = xorObfuscationDetected,
                verifiedObfuscatedPayload = verifiedObfuscatedPayload,
                cryptoApiDetected = cryptoApiDetected,
                hasOnlyDebuggerConnected = hasOnlyDebuggerConnected,
                hasOtherAntiAnalysis = hasOtherAntiAnalysis,
                receivers = receivers,
                services = services,
                deviceAdminEnabled = deviceAdminEnabled
            )

            var score = 0
            val matchedList = mutableListOf<String>()

            for (sig in SignatureEngine.signatures) {
                val points = sig.evaluate(state)
                if (points > 0) {
                    score += points
                    matchedList.add(sig.name)
                }
            }

            score = maxOf(0, minOf(100, score))

            val status = when {
                score < 40 -> TriageStatus.SAFE
                score < 75 -> TriageStatus.GREY_AREA
                else -> TriageStatus.MALICIOUS
            }

            return TriageResult(
                score = score,
                status = status,
                dangerousPermissions = dangerousPermissions,
                highEntropyDetected = highEntropyDetected,
                xorObfuscationDetected = xorObfuscationDetected,
                matchedPatterns = matchedList,
                extractedEvidence = extractedEvidence.toList()
            )
        }
    }
}
