plugins {
    kotlin("jvm") version "1.9.24"
    id("maven-publish")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")
    testImplementation("junit:junit:4.13.2")
}

publishing {
    publications {
        register<MavenPublication>("mavenJava") {
            groupId = "id.my.khuirulhuda.lib"
            artifactId = "liteapkparser"
            version = "1.0.0"

            from(components["java"])
        }
    }
}
