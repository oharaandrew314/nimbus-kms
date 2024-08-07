package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.KeyTypeException
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.proc.JWSVerifierFactory
import org.http4k.connect.amazon.kms.KMS
import java.security.Key

/**
 * Factory to verify signatures with the KMS API
 */
class KmsJwsVerifierFactory(private val kms: KMS): JWSVerifierFactory, BaseJWSProvider(supportedJwsAlgorithms) {

    override fun createJWSVerifier(header: JWSHeader, key: Key) : JWSVerifier {
        if (key !is KmsKey) throw KeyTypeException(KmsKey::class.java)
        return KmsJwsVerifier(kms, key.keyId)
    }
}