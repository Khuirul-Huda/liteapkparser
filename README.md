# LiteApkParser

LiteApkParser is a lightweight, high-performance offline-first static triage security scanning library (AAR) written in Clean Kotlin. It is specifically designed to run directly on Android devices under strict memory constraints. It identifies suspicious patterns, obfuscation, droppers, and dangerous permissions in Android APK files **without executing any code** and **without decompressing the entire APK to disk**.

---

## Key Features

*   **Low-Memory ZIP Stream Sequential Parser:** 
    Uses a custom circular byte buffer (8 KB) and `PushbackInputStream` layout synchronization to scan ZIP local file headers sequentially, bypassing the need to read or cache the Central Directory.
*   **Zero-Copy Binary XML Parser:**
    Directly parses Android's binary XML chunk layout (`AndroidManifest.xml`) to extract declared permissions, components, and Device Administrator bindings.
*   **Forward-Only DEX String Pool Parser:**
    Parses DEX file headers and streams string ID offsets sequentially, preventing out-of-order stream-skipping and JVM Out-Of-Memory (OOM) errors.
*   **XOR & Base64 Decryption Pipeline:**
    Automatically extracts high-entropy strings, decodes Base64 inputs, and brute-forces 1-byte XOR keys (`1..255`) to recursively triage hidden payloads.
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
println("Risk Score: ${result.score}")            // Int (0..100)
println("Triage Status: ${result.status}")       // SAFE, GREY_AREA, or DANGEROUS
println("Dangerous Perms: ${result.dangerousPermissions}")
println("Obfuscated payload found: ${result.xorObfuscationDetected}")
println("Matched Signatures: ${result.matchedPatterns}")
```

---

## Running Tests

To run the local JUnit unit tests:

```bash
# Run all unit tests
./gradlew test

# To run integration tests against a real APK, copy your target to the root directory
cp "/path/to/suspicious.apk" test.apk
./gradlew test
```

---

## License
Owned and developed by [Khuirul Huda](https://github.com/Khuirul-Huda).
Licensed under the Apache License, Version 2.0.
