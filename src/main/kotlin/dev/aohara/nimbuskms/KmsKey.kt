package dev.aohara.nimbuskms

import org.http4k.connect.amazon.core.model.KMSKeyId
import java.security.Key

/**
 * Reference to a remote KMS key for API verification
 */
internal data class KmsKey(val keyId: KMSKeyId): Key {
    override fun getAlgorithm() = null
    override fun getFormat() = null
    override fun getEncoded() = null
}