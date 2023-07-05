package dev.aohara.nimbuskms.examples

import com.nimbusds.jwt.SignedJWT
import dev.aohara.nimbuskms.KmsJwsVerifier
import org.http4k.connect.amazon.kms.Http
import org.http4k.connect.amazon.kms.KMS

fun main() {
    // Build a KMS remote verifier (it will call to KMS for each verification step)
    val kms = KMS.Http()
    val verifier = KmsJwsVerifier(kms)

    // parse the JWT
    val jwt = "abcd123943490rueroifgkjmdfvklmdcxklvmsdklfmdklgnjkfbnvjkdfvnjkdfvncsd"
        .let { SignedJWT.parse(it) }

    // Verify the JWT
    val verified: Boolean = jwt.verify(verifier)
    println("Verified: $verified")
}