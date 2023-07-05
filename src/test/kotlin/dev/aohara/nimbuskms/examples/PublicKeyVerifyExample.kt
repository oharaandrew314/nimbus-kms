package dev.aohara.nimbuskms.examples

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import dev.aohara.nimbuskms.KmsPublicKeyJwsKeySelector
import org.http4k.connect.amazon.kms.Http
import org.http4k.connect.amazon.kms.KMS

fun main() {
    val kms = KMS.Http()

    // to use the KMS public key, it's much simpler to use a JWTProcessor with the provided JWSKeySelector
    val processor = DefaultJWTProcessor<SecurityContext>().apply {
        jwsKeySelector = KmsPublicKeyJwsKeySelector(kms)
    }

    // parse the JWT
    val jwt = "abcd123943490rueroifgkjmdfvklmdcxklvmsdklfmdklgnjkfbnvjkdfvnjkdfvncsd"
        .let { SignedJWT.parse(it) }

    // verify the JWT
    val claims = processor.process(jwt, null)
    println(claims.subject)
}