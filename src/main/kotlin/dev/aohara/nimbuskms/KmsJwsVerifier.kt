package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.util.Base64URL
import dev.forkhandles.values.parseOrNull
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.KMS
import org.http4k.connect.amazon.kms.verify
import org.http4k.connect.model.Base64Blob

class KmsJwsVerifier(private val kms: KMS) : BaseJWSProvider(supportedJwsAlgorithms), JWSVerifier {

    override fun verify(header: JWSHeader, signedContent: ByteArray, signature: Base64URL): Boolean {
        val verifyResult = kms.verify(
            KeyId = KMSKeyId.parseOrNull(header.keyID) ?: throw KeySourceException("${header.keyID} is not a valid KMS key id"),
            SigningAlgorithm = header.algorithm.toHttp4kOrThrow(),
            Message = Base64Blob.encode(signedContent),
            Signature = Base64Blob.encode(signature.decode())
        ).valueOrThrow()

        return verifyResult.SignatureValid
    }
}