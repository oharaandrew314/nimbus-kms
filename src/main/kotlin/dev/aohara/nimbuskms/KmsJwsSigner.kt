package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.crypto.impl.ECDSA
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
        val http4kAlg = header.algorithm.toHttp4kOrThrow()

        val result = kms.sign(
            KeyId = keyId,
            SigningAlgorithm = http4kAlg,
            Message = Base64Blob.encode(signingInput)
        ).valueOrThrow()

        return result.Signature.decodedBytes()
            // KMS ECDSA signatures are in ASN.1/DER format.  JWS requires them to be in R+S format
            .let { if (!http4kAlg.isEcdsa()) it else ECDSA.transcodeSignatureToConcat(it, ECDSA.getSignatureByteArrayLength(header.algorithm)) }
            .let { Base64URL.encode(it) }
    }
}