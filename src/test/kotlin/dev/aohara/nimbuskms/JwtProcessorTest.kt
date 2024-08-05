package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.proc.BadJWSException
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Test

class JwtProcessorTest {

    @Test
    fun `process RSA jwt - verify with KMS`() {
        val key1 = newKey(CustomerMasterKeySpec.RSA_2048)

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsVerifierFactory = KmsJwsVerifierFactory(kms)
            jwsKeySelector = KmsJwsKeySelector(key1)
        }


        val jwt = key1.signJwt(JWSAlgorithm.RS256, sub = "kratos")

        val claims = processor.process(jwt, null)
        claims.subject shouldBe "kratos"
    }

    @Test
    fun `process ECDSA jwt - verify with KMS`() {
        val key1 = newKey(CustomerMasterKeySpec.ECC_NIST_P256)

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsVerifierFactory = KmsJwsVerifierFactory(kms)
            jwsKeySelector = KmsJwsKeySelector(key1)
        }

        val jwt = key1.signJwt(JWSAlgorithm.ES256, sub = "kratos")

        val claims = processor.process(jwt, null)
        claims.subject shouldBe "kratos"
    }

    @Test
    fun `process RSA jwt - expired`() {
        val key1 = newKey(CustomerMasterKeySpec.RSA_2048)

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsVerifierFactory = KmsJwsVerifierFactory(kms)
            jwsKeySelector = KmsJwsKeySelector(key1)
        }


        val jwt = key1.signJwt(JWSAlgorithm.RS256, sub = "kratos", expires = clock.instant().minusSeconds(60))

        shouldThrow<BadJWTException> {
            processor.process(jwt, null)
        }.message shouldBe "Expired JWT"
    }

    @Test
    fun `process RSA jwt - invalid signature`() {
        val key1 = newKey(CustomerMasterKeySpec.RSA_2048)
        val key2 = newKey(CustomerMasterKeySpec.RSA_2048)

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsVerifierFactory = KmsJwsVerifierFactory(kms)
            jwsKeySelector = KmsJwsKeySelector(key2)
        }

        val jwt = key1.signJwt(JWSAlgorithm.RS256, sub = "kratos")

        shouldThrow<BadJWSException> {
            processor.process(jwt, null)
        }.message shouldBe "Signed JWT rejected: Invalid signature"
    }

    @Test
    fun `process RSA jwt - verify with KMS public key`() {
        val key1 = newKey(CustomerMasterKeySpec.RSA_2048)

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsKeySelector = KmsPublicKeyJwsKeySelector(kms, key1)
        }

        val jwt = key1.signJwt(JWSAlgorithm.RS256, sub = "Athena")

        val claims = processor.process(jwt, null)
        claims.subject shouldBe "Athena"
    }

    @Test
    fun `process ECDSA jwt - verify with KMS public key`() {
        val key1 = newKey(CustomerMasterKeySpec.ECC_NIST_P256)

        val processor = DefaultJWTProcessor<SecurityContext>().apply {
            jwtClaimsSetVerifier = DeterministicJwtClaimSetVerifier(clock)
            jwsKeySelector = KmsPublicKeyJwsKeySelector(kms, key1, BouncyCastleProviderSingleton.getInstance())
            jwsVerifierFactory.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
        }

        val jwt = key1.signJwt(JWSAlgorithm.ES256, sub = "Athena")

        val claims = processor.process(jwt, null)
        claims.subject shouldBe "Athena"
    }
}