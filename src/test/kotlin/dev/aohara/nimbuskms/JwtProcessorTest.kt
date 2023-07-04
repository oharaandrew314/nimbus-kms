package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.kotest.matchers.shouldBe
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Test

class JwtProcessorTest {

    @Test
    fun `process jwt - verify with KMS`() {
        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsVerifierFactory = KmsJwsVerifierFactory(kms)
            jwsKeySelector = KmsJwsKeySelector()
        }

        val key1 = newKey(CustomerMasterKeySpec.RSA_2048)
        val jwt = key1.signJwt(JWSAlgorithm.RS256, sub = "kratos")

        val claims = processor.process(jwt, null)
        claims.subject shouldBe "kratos"
    }

    @Test
    fun `process jwt - verify with KMS public key`() {
        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsKeySelector = KmsPublicKeyJwsKeySelector(kms)
        }

        val key1 = newKey(CustomerMasterKeySpec.RSA_2048)
        val jwt = key1.signJwt(JWSAlgorithm.RS256, sub = "Athena")

        val claims = processor.process(jwt, null)
        claims.subject shouldBe "Athena"
    }
}