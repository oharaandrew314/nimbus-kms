package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.util.Base64URL
import dev.forkhandles.result4k.Failure
import dev.forkhandles.result4k.Success
import dev.forkhandles.result4k.flatMapFailure
import dev.forkhandles.result4k.map
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.KMS
import org.http4k.connect.amazon.kms.verify
import org.http4k.connect.model.Base64Blob

/**
 * Verify a signature with the KMS API
 */
internal class KmsJwsVerifier(private val kms: KMS, private val keyId: KMSKeyId) : BaseJWSProvider(supportedJwsAlgorithms), JWSVerifier {

    override fun verify(header: JWSHeader, signedContent: ByteArray, signature: Base64URL): Boolean {
        val http4kAlg = header.algorithm.toHttp4kOrThrow()

        return kms.verify(
            KeyId = keyId,
            SigningAlgorithm = http4kAlg,
            Message = Base64Blob.encode(signedContent),
            Signature = signature
                .decode()
                .let { if (!http4kAlg.isEcdsa()) it else ECDSA.transcodeSignatureToDER(it) }
                .let { Base64Blob.encode(it) }
        ).map { it.SignatureValid }
            .flatMapFailure { if ("KMSInvalidSignatureException" in (it.message ?: "")) Success(false) else Failure(it) }
            .valueOrThrow()
    }
}