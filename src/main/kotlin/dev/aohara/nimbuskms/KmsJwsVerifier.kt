package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.KeyTypeException
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerifierFactory
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.Base64URL
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.KMS
import org.http4k.connect.amazon.kms.verify
import org.http4k.connect.model.Base64Blob
import java.security.Key

/**
 * Verify a signature with the KMS API
 */
class KmsJwsVerifier(private val kms: KMS, private val keyId: KMSKeyId) : BaseJWSProvider(supportedJwsAlgorithms), JWSVerifier {

    override fun verify(header: JWSHeader, signedContent: ByteArray, signature: Base64URL): Boolean {
        val verifyResult = kms.verify(
            KeyId = keyId,
            SigningAlgorithm = header.algorithm.toHttp4kOrThrow(),
            Message = Base64Blob.encode(signedContent),
            Signature = Base64Blob.encode(signature.decode())
        ).valueOrThrow()

        return verifyResult.SignatureValid
    }
}

/**
 * Factory to verify signatures with the KMS API
 */
class KmsJwsVerifierFactory(private val kms: KMS): JWSVerifierFactory, BaseJWSProvider(supportedJwsAlgorithms) {

    override fun createJWSVerifier(header: JWSHeader, key: Key) : KmsJwsVerifier {
        if (key !is KmsKey) throw  KeyTypeException(KmsKey::class.java)
        return KmsJwsVerifier(kms, key.keyId)
    }
}

/**
 * Use the KMS API to verify signatures
 */
class KmsJwsKeySelector<C: SecurityContext>(private val keyId: KMSKeyId): JWSKeySelector<C> {

    override fun selectJWSKeys(header: JWSHeader, context: C?): List<Key> {
        return listOf(KmsKey(keyId))
    }
}

/**
 * Reference to a remote KMS key for API verification
 */
private data class KmsKey(val keyId: KMSKeyId): Key {
    override fun getAlgorithm() = null
    override fun getFormat() = null
    override fun getEncoded() = null
}