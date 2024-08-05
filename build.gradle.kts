import com.vanniktech.maven.publish.SonatypeHost
import com.vanniktech.maven.publish.KotlinJvm

plugins {
    kotlin("jvm")
    id("maven-publish")
    id("com.vanniktech.maven.publish")
    id("jacoco")
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
    testImplementation("dev.forkhandles:result4k-kotest:_")
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

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
    }
}

mavenPublishing {
    configure(KotlinJvm(sourcesJar = true))
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
    signAllPublications()
    coordinates("dev.andrewohara", "nimbus-kms", "0.1")

    pom {
        name.set("Nimbus KMS")
        description.set("Collection of useful kotlin microservice utilities")
        inceptionYear.set("2023")
        url.set("https://github.com/oharaandrew314/nimbus-kms")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("oharaandrew314")
                name.set("Andrew O'Hara")
                url.set("https://github.com/oharaandrew314")
            }
        }
        scm {
            url.set("https://github.com/oharaandrew314/nimbus-kms")
        }
    }
}