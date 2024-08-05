package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import org.http4k.connect.amazon.core.model.KMSKeyId
import java.security.Key

/**
 * Use the KMS API to verify signatures
 */
class KmsJwsKeySelector<C: SecurityContext>(private val keyId: KMSKeyId): JWSKeySelector<C> {

    override fun selectJWSKeys(header: JWSHeader, context: C?): List<Key> {
        return listOf(KmsKey(keyId))
    }
}