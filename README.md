# LiteApkParser

LiteApkParser is a lightweight, high-performance offline-first static triage security scanning library (AAR) written in Clean Kotlin. It is specifically designed to run directly on Android devices under strict memory constraints. It identifies suspicious patterns, obfuscation, droppers, and dangerous permissions in Android APK files **without executing any code** and **without decompressing the entire APK to disk**.

> [!IMPORTANT]
> **Disclaimer:** This tool is designed strictly for **educational purposes**, authorized research, and security analysis of Android packages. It must not be used for unauthorized target scanning or malicious activity. The author assumes no liability for misuse or damage caused by this utility.

---

## Key Features

*   **Low-Memory ZIP Stream Sequential Parser:** 
    Uses a custom circular byte buffer (8 KB) and `PushbackInputStream` layout synchronization to scan ZIP local file headers sequentially, bypassing the need to read or cache the Central Directory.
*   **Zero-Copy Binary XML Parser:**
    Directly parses Android's binary XML chunk layout (`AndroidManifest.xml`) to extract declared permissions, and collects registered component names (receivers, services, device administrators) to detect suspicious class patterns.
*   **Forward-Only DEX String Pool Parser:**
    Parses DEX file headers and streams string ID offsets sequentially, preventing out-of-order stream-skipping and JVM Out-Of-Memory (OOM) errors.
*   **Deep Deobfuscation & Decryption Engine:**
    *   **1-Byte XOR & Base64 Decoder:** Automatically decodes Base64 inputs, and brute-forces 1-byte XOR keys (`0..255`) recursively.
    *   **Candidate-based AES Decryptor:** Collects candidate key and ciphertext strings from the DEX pool and attempts automated decryption (ECB & CBC modes) during static scanning.
    *   **16-Bit Short Array Brute-Forcer:** Searches raw DEX bytecode for 16-bit static array initializer payloads (`00 03 02 00` array-data headers) and brute-forces GPR/XOR keys (`0..65535`) to reverse custom Unicode/identifier encryption dynamically.
    *   **Evidence Collection:** Automatically extracts and records decrypted C2 domains, Telegram API credentials, exfiltrated texts, or hidden URL configurations.
*   **Refined Heuristics:**
    *   XOR bytecode loops verification (requires conditional branch instruction checks).
    *   Exclusion of standard classpath loader patterns (e.g., `PathClassLoader`) to prevent false positives.
    *   Anti-analysis API tracking (e.g., debug-checks, Frida, Xposed).

---

## Getting Started

### Local Installation & Consumption

To use LiteApkParser in your own Android application, publish it locally to your Maven cache:

1.  **Publish to Maven Local:**
    ```bash
    ./gradlew publishToMavenLocal
    ```

2.  **Enable Maven Local in your Application's repository configuration:**
    ```kotlin
    // settings.gradle.kts (or root build.gradle.kts)
    dependencyResolutionManagement {
        repositories {
            google()
            mavenCentral()
            mavenLocal() // <--- Add this!
        }
    }
    ```

3.  **Add the Dependency:**
    ```kotlin
    // app/build.gradle.kts
    dependencies {
        implementation("id.my.khuirulhuda.lib:liteapkparser:1.0.0")
    }
    ```

---

## API Usage

Using the library to analyze an APK is extremely simple:

```kotlin
import id.my.khuirulhuda.lib.liteapkparser.LiteApkParser
import java.io.File

// Initialize the parser
val parser = LiteApkParser()

// Point to the APK file
val apkFile = File("/path/to/target.apk")

// Run static triage analysis
val result = parser.analyzeApk(apkFile)

// Access analysis metrics
println("Risk Score: ${result.score}")                 // Int (0..100)
println("Triage Status: ${result.status}")             // SAFE, GREY_AREA, or MALICIOUS
println("Dangerous Perms: ${result.dangerousPermissions}")
println("Obfuscated payload found: ${result.xorObfuscationDetected}")
println("Matched Signatures: ${result.matchedPatterns}")
println("Extracted Evidence: ${result.extractedEvidence}") // Lists decrypted URLs, Bot Tokens, C2 Domains
```

### Sample Triage Output

Below is an example of the structured triage results returned when scanning a real SMS stealer payload (`malicious_sms_rce_telegram.apk`):

```json
{
  "score": 100,
  "status": "MALICIOUS",
  "dangerousPermissions": [
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS"
  ],
  "highEntropyDetected": false,
  "xorObfuscationDetected": true,
  "matchedPatterns": [
    "NATIVE_EXECUTION",
    "TELEGRAM_BOT",
    "SUSPICIOUS_COMPONENT",
    "SMS_STEALER"
  ],
  "extractedEvidence": [
    "https://api.telegram.org/bot*****/sendMessage?parse_mode=markdown&chat_id=******&text=*",
    "https://api.telegram.org/bot******/sendMessage?parse_mode=markdown&chat_id=******&text=SOme Text * %0A*Kepada* : _"
  ]
}
```

---

## Running Tests

To run the local JUnit unit tests:

```bash
# Run all unit tests
./gradlew test

# To run integration tests against a real APK, copy your target to the root directory
# and run the test suite to observe decrypted evidence dumps
./gradlew test --info
```

---

## License
Owned and developed by [Khuirul Huda](https://github.com/Khuirul-Huda).  
Licensed under the Apache License, Version 2.0.
