package dev.aohara.nimbuskms.examples

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.aohara.nimbuskms.KmsJwsSigner
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.Http
import org.http4k.connect.amazon.kms.KMS
import java.time.Duration
import java.time.Instant
import java.util.Date

fun main() {
    val kms = KMS.Http()
    val jwsSigner = KmsJwsSigner(kms)
    val keyId = KMSKeyId.of("my_kms_key_id")

    // set all the JWT claims we want for our principal
    val claims = JWTClaimsSet.Builder()
        .subject("person1")
        .issuer("myapp")
        .claim("foo", "bar")
        .expirationTime(Date.from(Instant.now() + Duration.ofHours(1)))
        .build()

    // Configure the KMS key and algorithm to use for signing
    val header = JWSHeader.Builder(JWSAlgorithm.RS256)
        .keyID(keyId.value)  // important!  Necessary to load the key for signing and verifying
        .build()

    // Build, sign, and serialize the JWT
    val jwt = SignedJWT(header, claims)
        .also { it.sign(jwsSigner) }
        .serialize()

    println(jwt)
}