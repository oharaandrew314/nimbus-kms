package dev.aohara.nimbuskms

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

class KmsJwsVerifierTest {

    private val key = newKey(CustomerMasterKeySpec.RSA_4096)

    @Test
    fun `sign and verify`() {
        val jwt = key.signJwt(JWSAlgorithm.RS512)
        key.verifyJwt(jwt) shouldBe true
    }

    @Test
    @Disabled("Fake KMS must only verify signatures of the correct key")
    fun `verification fails - invalid key`() {
        val jwt = key.signJwt(alg = JWSAlgorithm.PS512)
        newKey(CustomerMasterKeySpec.RSA_3072).verifyJwt(jwt) shouldBe false
    }

    @Test
    fun `verification fails - unsupported algorithm`() {
        val jwt = SignedJWT.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

        shouldThrow<JOSEException> {
            key.verifyJwt(jwt)
        }.message shouldBe "Unsupported algorithm: HS256"
    }
}