package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import io.kotest.matchers.shouldBe
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Test

class KmsJwsVerifierTest {

    @Test
    fun `sign and verify - RSA`() {
        val keyId = newKey(CustomerMasterKeySpec.RSA_4096)
        val jwt = keyId.signJwt(JWSAlgorithm.RS512)

        val verifier = KmsJwsVerifier(kms, keyId)
        jwt.verify(verifier) shouldBe true
    }

    @Test
    fun `sign and verify - ECDSA`() {
        val keyId = newKey(CustomerMasterKeySpec.ECC_NIST_P256)
        val jwt = keyId.signJwt(JWSAlgorithm.ES256)

        val verifier = KmsJwsVerifier(kms, keyId)
        jwt.verify(verifier) shouldBe true
    }

    @Test
    fun `verification fails - invalid signature`() {
        val keyId = newKey(CustomerMasterKeySpec.RSA_4096)
        val jwt = keyId.signJwt(JWSAlgorithm.RS256)

        val otherKeyId = newKey(CustomerMasterKeySpec.RSA_4096)
        val verifier = KmsJwsVerifier(kms, otherKeyId)

        jwt.verify(verifier) shouldBe false
    }
}