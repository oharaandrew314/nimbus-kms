package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.util.Base64URL
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.KMS
import org.http4k.connect.amazon.kms.sign
import org.http4k.connect.model.Base64Blob

/**
 * Use the KMS API to sign messages
 */
class KmsJwsSigner(private val kms: KMS, private val keyId: KMSKeyId) : BaseJWSProvider(supportedJwsAlgorithms), JWSSigner {

    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
        val result = kms.sign(
            KeyId = keyId,
            SigningAlgorithm = header.algorithm.toHttp4kOrThrow(),
            Message = Base64Blob.Companion.encode(signingInput)
        ).valueOrThrow()

        return Base64URL.encode(result.Signature.decodedBytes())
    }
}