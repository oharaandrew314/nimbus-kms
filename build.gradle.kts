plugins {
    kotlin("jvm")
    id("maven-publish")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("org.http4k:http4k-connect-bom:_"))

    api("com.nimbusds:nimbus-jose-jwt:_")
    api("org.http4k:http4k-connect-amazon-kms")

    testImplementation(kotlin("test"))
    testImplementation("org.http4k:http4k-connect-amazon-kms-fake")
    testImplementation("io.kotest:kotest-assertions-core-jvm:_")
    testImplementation("org.bouncycastle:bcprov-jdk18on:_")
    testImplementation("org.bouncycastle:bcpkix-jdk18on:_")
    testImplementation("dev.forkhandles:result4k-kotest")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}

tasks.compileKotlin {
    compilerOptions {
        allWarningsAsErrors = true
    }
}

tasks {
    val sourcesJar by creating(Jar::class) {
        archiveClassifier.set("sources")
        artifacts {
            kotlinSourcesJar
        }
    }

    artifacts {
        archives(sourcesJar)
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["kotlin"])
        }
    }
}