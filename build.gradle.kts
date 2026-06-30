plugins {
    id("com.android.library") version "8.4.0"
    kotlin("android") version "1.9.24"
    id("maven-publish")
}

android {
    namespace = "id.my.khuirulhuda.lib.liteapkparser"
    compileSdk = 34

    defaultConfig {
        minSdk = 21

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "id.my.khuirulhuda.lib"
            artifactId = "liteapkparser"
            version = "1.0.0"

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}
