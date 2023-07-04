package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SecurityContext
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.types.shouldBeInstanceOf
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class KmsPublicKeyJwsKeySelectorTest {

    private val factory = KmsPublicKeyJwsKeySelector<SecurityContext>(kms)

    @Test
    fun `download and verify RSA key`() {
        val keyId = newKey(CustomerMasterKeySpec.RSA_2048)
        val keyData = KmsKey(keyId, JWSAlgorithm.RS256)

        val jwt = keyData.signJwt()

        factory.selectJWSKeys(jwt.header, null)
            .shouldHaveSize(1)
            .first().shouldBeInstanceOf<RSAPublicKey>()
    }

    @Test
    @Disabled("Fake KMS must support ECDSA public key generation")
    fun `download and verify ECDSA key`() {
        val keyId = newKey(CustomerMasterKeySpec.ECC_NIST_P256)
        val keyData = KmsKey(keyId, JWSAlgorithm.ES256)

        val jwt = keyData.signJwt()

        factory.selectJWSKeys(jwt.header, null)
            .shouldHaveSize(1)
            .first().shouldBeInstanceOf<ECPublicKey>()
    }
}