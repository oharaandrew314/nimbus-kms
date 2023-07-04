package dev.aohara.nimbuskms

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import dev.forkhandles.values.parseOrNull
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.KMS
import org.http4k.connect.amazon.kms.getPublicKey
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import java.security.Key
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec

/**
 * Download KMS public keys to verify signatures locally.
 *
 * Note: ECDSA keys require a cryptographic provider.  For example:
 * Security.addProvider(BouncyCastleProvider())
 */
class KmsPublicKeyJwsKeySelector<C: SecurityContext>(private val kms: KMS): JWSKeySelector<C> {

    override fun selectJWSKeys(header: JWSHeader, context: C?): List<Key> {
        val keyId = KMSKeyId.parseOrNull(header.keyID) ?: throw KeySourceException("${header.keyID} is not a valid KMS key id")

        val publicKeyData = kms.getPublicKey(keyId).valueOrThrow()
        val keySpec = X509EncodedKeySpec(publicKeyData.PublicKey.decodedBytes())

        val alg = when(publicKeyData.CustomerMasterKeySpec) {
            CustomerMasterKeySpec.RSA_2048, CustomerMasterKeySpec.RSA_3072, CustomerMasterKeySpec.RSA_4096 -> "RSA"
            CustomerMasterKeySpec.ECC_NIST_P256, CustomerMasterKeySpec.ECC_NIST_P384, CustomerMasterKeySpec.ECC_NIST_P521 -> "ECDSA"
            CustomerMasterKeySpec.ECC_SECG_P256K1, CustomerMasterKeySpec.SYMMETRIC_DEFAULT ->
                throw JOSEException("Unsupported key spec: ${publicKeyData.CustomerMasterKeySpec}")
        }

        val publicKey = KeyFactory.getInstance(alg).generatePublic(keySpec)
        return listOf(publicKey)
    }
}