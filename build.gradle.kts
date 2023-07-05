plugins {
    kotlin("jvm") version "1.8.22"
}

repositories {
    mavenCentral()
}

dependencies {
    kotlin("stdlib-jdk8")
    implementation(platform("org.http4k:http4k-connect-bom:5.0.1.0"))

    api("com.nimbusds:nimbus-jose-jwt:9.31")
    api("org.http4k:http4k-connect-amazon-kms")

    testImplementation(kotlin("test"))
    testImplementation("org.http4k:http4k-connect-amazon-kms-fake")
    testImplementation("io.kotest:kotest-assertions-core-jvm:5.5.4")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}

tasks.compileKotlin {
    kotlinOptions {
        allWarningsAsErrors = true
    }
}