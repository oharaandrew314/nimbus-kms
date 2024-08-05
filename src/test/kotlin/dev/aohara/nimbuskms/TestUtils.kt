package dev.aohara.nimbuskms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.forkhandles.result4k.kotest.shouldBeSuccess
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.FakeKMS
import org.http4k.connect.amazon.kms.createKey
import org.http4k.connect.amazon.kms.model.CustomerMasterKeySpec
import org.http4k.connect.amazon.kms.model.KeyUsage
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date

val kms = FakeKMS().client()
val clock: Clock = Clock.fixed(Instant.parse("2023-05-29T12:00:00Z"), ZoneOffset.UTC)

fun newKey(
    spec: CustomerMasterKeySpec,
    usage: KeyUsage = KeyUsage.SIGN_VERIFY
): KMSKeyId {
    return kms.createKey(spec, usage)
        .shouldBeSuccess()
        .KeyMetadata.KeyId
}

fun KMSKeyId.signJwt(
    alg: JWSAlgorithm,
    sub: String = "kratos",
    iss: String = "dev.aohara.nimbuskms",
    expires: Instant = clock.instant() + Duration.ofHours(1),
): SignedJWT {
    val claimsSet = JWTClaimsSet.Builder()
        .subject(sub)
        .issuer(iss)
        .expirationTime(Date.from(expires))
        .build()

    val header = JWSHeader.Builder(alg)
        .build()

    val signer = KmsJwsSigner(kms, this)

    return SignedJWT(header, claimsSet).apply {
        sign(signer)
    }
}