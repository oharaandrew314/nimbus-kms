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
    // Build KMS client and get key id
    val kms = KMS.Http()
    val kmsKeyId = KMSKeyId.of("my_kms_key_id")

    // Build a basic signer
    val jwsSigner = KmsJwsSigner(kms, kmsKeyId)

    // set all the JWT claims we want for our principal
    val claims = JWTClaimsSet.Builder()
        .subject("person1")
        .issuer("myapp")
        .claim("foo", "bar")
        .expirationTime(Date.from(Instant.now() + Duration.ofHours(1)))
        .build()

    // Configure the algorithm to use for signing
    val header = JWSHeader.Builder(JWSAlgorithm.RS256).build()

    // Build, sign, and serialize the JWT
    val jwt = SignedJWT(header, claims)
        .also { it.sign(jwsSigner) }
        .serialize()

    println(jwt)
}