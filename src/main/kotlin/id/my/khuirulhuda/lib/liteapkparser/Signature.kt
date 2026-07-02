package id.my.khuirulhuda.lib.liteapkparser

internal data class ScanningState(
    val permissions: List<String>,
    val strings: Set<String>,
    val decrypted: Set<String>,
    val highEntropyDetected: Boolean,
    val xorObfuscationDetected: Boolean,
    val verifiedObfuscatedPayload: Boolean,
    val cryptoApiDetected: Boolean,
    val hasOnlyDebuggerConnected: Boolean,
    val hasOtherAntiAnalysis: Boolean,
    val receivers: List<String>,
    val services: List<String>,
    val deviceAdminEnabled: Boolean
) {
    val hasSms = permissions.contains("android.permission.RECEIVE_SMS") ||
                 permissions.contains("android.permission.SEND_SMS")
    val hasAccessibility = permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
    val hasInstaller = permissions.contains("android.permission.REQUEST_INSTALL_PACKAGES") ||
                       permissions.contains("android.permission.INSTALL_PACKAGES")
}

internal interface Signature {
    val name: String
    fun evaluate(state: ScanningState): Int
}

internal object SignatureEngine {
    val signatures: List<Signature> = listOf(
        PermissionAbuseSignature(),
        SilentInstallSignature(),
        AntiAnalysisSignature(),
        NativeExecutionSignature(),
        CryptoEntropySignature(),
        XorObfuscationSignature(),
        TelegramBotSignature(),
        SmsStealerSignature(),
        DropperSignature(),
        SuspiciousComponentSignature(),
        DeviceAdminSignature()
    )
}

// 1. Permission Abuse Signature
internal class PermissionAbuseSignature : Signature {
    override val name = "PERMISSION_ABUSE"
    override fun evaluate(state: ScanningState): Int {
        return if (state.hasSms || state.hasAccessibility || state.hasInstaller) 25 else 0
    }
}

// 2. Silent Install Signature
internal class SilentInstallSignature : Signature {
    override val name = "SILENT_INSTALL"

    override fun evaluate(state: ScanningState): Int {
        val allStrings = state.strings + state.decrypted
        val matches = allStrings.any { s ->
            s.contains("pm install") ||
            s.contains("cmd package install") ||
            s.contains("application/vnd.android.package-archive") ||
            s.contains("PackageInstaller\$Session") ||
            s.contains("DexClassLoader") ||
            (s.contains("PathClassLoader") && s != "Ldalvik/system/PathClassLoader;" && s != "dalvik.system.PathClassLoader")
        }
        if (matches) {
            return if (state.verifiedObfuscatedPayload || state.hasInstaller || state.hasAccessibility) 25 else 10
        }
        return 0
    }
}

// 3. Anti-Analysis Signature
internal class AntiAnalysisSignature : Signature {
    override val name = "ANTI_ANALYSIS"

    override fun evaluate(state: ScanningState): Int {
        val allStrings = state.strings + state.decrypted
        val matches = allStrings.any { s ->
            s.contains("ro.kernel.qemu") ||
            s.contains("ro.product.model") ||
            s.contains("isDebuggerConnected") ||
            s.contains("frida:rpc") ||
            s.contains("xposed.installer")
        }
        if (matches) {
            return if (state.hasOnlyDebuggerConnected && !state.hasOtherAntiAnalysis) 5 else 15
        }
        return 0
    }
}

// 4. Native Execution Signature
internal class NativeExecutionSignature : Signature {
    override val name = "NATIVE_EXECUTION"

    override fun evaluate(state: ScanningState): Int {
        val allStrings = state.strings + state.decrypted
        val matches = allStrings.any { s ->
            s.contains("Runtime.getRuntime().exec") ||
            s == "/system/bin/sh" ||
            s == "/system/bin/su" ||
            s == "sh" || s == "su" ||
            s == "su -c"
        }
        return if (matches) 15 else 0
    }
}

// 5. Crypto & Entropy Signature
internal class CryptoEntropySignature : Signature {
    override val name = "CRYPTO_ENTROPY"
    override fun evaluate(state: ScanningState): Int {
        return if (state.highEntropyDetected && state.cryptoApiDetected) 20 else 0
    }
}

// 6. XOR Obfuscation Signature
internal class XorObfuscationSignature : Signature {
    override val name = "XOR_OBFUSCATION"
    override fun evaluate(state: ScanningState): Int {
        return if (state.xorObfuscationDetected) 15 else 0
    }
}

// 7. Telegram Bot Signature
internal class TelegramBotSignature : Signature {
    override val name = "TELEGRAM_BOT"

    override fun evaluate(state: ScanningState): Int {
        val allStrings = state.strings + state.decrypted
        val matches = allStrings.any { s ->
            s.contains("api.telegram.org") ||
            s == "botToken" ||
            s == "bot_token" ||
            s == "botToken2" ||
            (s.contains("/sendMessage") && s.contains("bot"))
        }
        return if (matches) 25 else 0
    }
}

// 8. SMS Stealer Signature
internal class SmsStealerSignature : Signature {
    override val name = "SMS_STEALER"
    override fun evaluate(state: ScanningState): Int {
        val hasBot = TelegramBotSignature().evaluate(state) > 0
        return if (state.hasSms && hasBot) 25 else 0
    }
}

// 9. Dropper Signature
internal class DropperSignature : Signature {
    override val name = "DROPPER"
    override fun evaluate(state: ScanningState): Int {
        val hasSilentInstall = SilentInstallSignature().evaluate(state) > 0
        return if (state.hasInstaller && hasSilentInstall) 20 else 0
    }
}

// 10. Suspicious Component Signature
internal class SuspiciousComponentSignature : Signature {
    override val name = "SUSPICIOUS_COMPONENT"
    override fun evaluate(state: ScanningState): Int {
        val suspiciousComponentNames = listOf("ReceiveSms", "SendSMS", "SMSReceiver", "SmsReceiver", "NotificationService")
        val matchReceivers = state.receivers.any { rec ->
            suspiciousComponentNames.any { rec.endsWith(it) || rec.contains(".$it") }
        }
        val matchServices = state.services.any { srv ->
            suspiciousComponentNames.any { srv.endsWith(it) || srv.contains(".$it") }
        }
        return if (matchReceivers || matchServices) 20 else 0
    }
}

// 11. Device Admin Signature
internal class DeviceAdminSignature : Signature {
    override val name = "DEVICE_ADMIN"
    override fun evaluate(state: ScanningState): Int {
        return if (state.deviceAdminEnabled) 20 else 0 // Let's keep device admin points consistent
    }
}
