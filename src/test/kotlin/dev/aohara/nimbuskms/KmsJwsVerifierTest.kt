package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import io.kotest.matchers.shouldBe
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

class KmsJwsVerifierTest {

    private val keyId = newKey(CustomerMasterKeySpec.RSA_4096)
    private val verifier = KmsJwsVerifier(kms, keyId)

    @Test
    fun `sign and verify`() {
        val jwt = keyId.signJwt(JWSAlgorithm.RS512)

        jwt.verify(verifier) shouldBe true
    }

    @Test
    @Disabled("Fake KMS must support key validation on verify")
    fun `verification fails - invalid key`() {
        val jwt = "eyJraWQiOiI1Y2E3YjlmMS00YWNlLTQ0YTktYmFmNS0yMjM2ZTA3OWRiNzgiLCJhbGciOiJQUzUxMiJ9.eyJpc3MiOiJkZXYuYW9oYXJhLm5pbWJ1c2ttcyIsInN1YiI6ImtyYXRvcyIsImV4cCI6MTY4NTM2NTIwMH0.TPBVr90ptbPFJ7qB4bLmw4YU5bckRYAovua4za6yY7DT-W0w1e0HOI3KS2sbgJ6nKk5BQvZBoRA9g8HHW18y-3rxme0tW6Eyl2UsDR_rPopEBQxDrAKg72ubzcbe4Sjs5WDzlXgeqi931fOdTMXaN072RF2-BwRGUU09EQbpm2ZUcBhjo_AswWCJROq2u9b512AgJ8ySWHur51S7lfdhgKKfuNqKIDSZ4UWkwh_11GH0Wtvse6GVz5ecWrOtcrmFWKKQR78HOfSxIX6z13Vo3vu0oFUgiX1yJN1673VxQEcU5uxr8gaE5drjy2Do5G8oP7Jm062WwRSIhgQTBRBvyg"
            .let { SignedJWT.parse(it) }

        jwt.verify(verifier) shouldBe false
    }
}