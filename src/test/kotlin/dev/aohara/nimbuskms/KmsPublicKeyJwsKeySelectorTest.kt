package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.proc.SecurityContext
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Test
import java.security.NoSuchAlgorithmException
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class KmsPublicKeyJwsKeySelectorTest {

    @Test
    fun `download and verify RSA key`() {
        val keyId = newKey(CustomerMasterKeySpec.RSA_2048)
        val selector = KmsPublicKeyJwsKeySelector<SecurityContext>(kms, keyId)

        val jwt = keyId.signJwt(JWSAlgorithm.RS512)

        val publicKey = selector.selectJWSKeys(jwt.header, null)
            .shouldHaveSize(1)
            .first().shouldBeInstanceOf<RSAPublicKey>()

        val verifier = RSASSAVerifier(publicKey)
        jwt.verify(verifier) shouldBe true
    }

    @Test
    fun `download and verify ECDSA key - without bouncycastle`() {
        val keyId = newKey(CustomerMasterKeySpec.ECC_NIST_P256)
        val selector = KmsPublicKeyJwsKeySelector<SecurityContext>(kms, keyId)

        val jwt = keyId.signJwt(JWSAlgorithm.ES256)

        shouldThrow<NoSuchAlgorithmException> {
            selector.selectJWSKeys(jwt.header, null)
        }
    }

    @Test
    fun `download and verify ECDSA key - with BouncyCastle`() {
        val keyId = newKey(CustomerMasterKeySpec.ECC_NIST_P521)
        val selector = KmsPublicKeyJwsKeySelector<SecurityContext>(kms, keyId, BouncyCastleProviderSingleton.getInstance())

        val jwt = keyId.signJwt(JWSAlgorithm.ES512)

        val publicKey = selector.selectJWSKeys(jwt.header, null)
            .shouldHaveSize(1)
            .first().shouldBeInstanceOf<ECPublicKey>()

        val verifier = ECDSAVerifier(publicKey).apply {
            jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
        }
        jwt.verify(verifier) shouldBe true
    }
}