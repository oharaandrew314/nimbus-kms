package dev.aohara.nimbuskms

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import org.http4k.connect.amazon.kms.model.SigningAlgorithm

private val supportedAlgorithms = mapOf(
    JWSAlgorithm.ES256 to SigningAlgorithm.ECDSA_SHA_256,
    JWSAlgorithm.ES384 to SigningAlgorithm.ECDSA_SHA_384,
    JWSAlgorithm.ES512 to SigningAlgorithm.ECDSA_SHA_512,
    JWSAlgorithm.RS256 to SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256,
    JWSAlgorithm.RS384 to SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_384,
    JWSAlgorithm.RS512 to SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_512,
    JWSAlgorithm.PS256 to SigningAlgorithm.RSASSA_PSS_SHA_256,
    JWSAlgorithm.PS384 to SigningAlgorithm.RSASSA_PSS_SHA_384,
    JWSAlgorithm.PS512 to SigningAlgorithm.RSASSA_PSS_SHA_512
)

val supportedJwsAlgorithms get() = supportedAlgorithms.keys

fun JWSAlgorithm.toHttp4kOrThrow() = supportedAlgorithms[this] ?: throw JOSEException("Unsupported algorithm: $this")

