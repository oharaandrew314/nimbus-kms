package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import dev.forkhandles.values.parseOrNull
import org.http4k.connect.amazon.core.model.KMSKeyId

/**
 * Use the KMS API to verify signatures
 */
class KmsJwsKeySelector<C: SecurityContext>: JWSKeySelector<C> {

    override fun selectJWSKeys(header: JWSHeader, context: C?): List<KmsKey> {
        val keyId = KMSKeyId.parseOrNull(header.keyID) ?: throw KeySourceException("${header.keyID} is not a valid KMS key id")
        return listOf(KmsKey(keyId, header.algorithm))
    }
}