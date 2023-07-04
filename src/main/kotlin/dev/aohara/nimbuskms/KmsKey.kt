package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.KeyTypeException
import org.http4k.connect.amazon.core.model.KMSKeyId
import java.security.Key

/**
 * Reference to a remote KMS key for API verification
 */
data class KmsKey(
    val keyId: KMSKeyId,
    val algorithm: JWSAlgorithm
): Key {
    override fun getAlgorithm(): String = algorithm.name
    override fun getFormat() = null
    override fun getEncoded() = null
}

fun Key.asKmsOrThrow() = this as? KmsKey ?: throw KeyTypeException(KmsKey::class.java)