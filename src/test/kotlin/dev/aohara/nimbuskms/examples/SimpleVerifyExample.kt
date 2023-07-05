package dev.aohara.nimbuskms.examples

import com.nimbusds.jwt.SignedJWT
import dev.aohara.nimbuskms.KmsJwsVerifier
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.Http
import org.http4k.connect.amazon.kms.KMS

fun main() {
    // Build KMS client and load the key id
    val kms = KMS.Http()
    val kmsKeyId = KMSKeyId.of("your_kms_key_id")

    // Build the verifier
    val verifier = KmsJwsVerifier(kms, kmsKeyId)

    // parse the JWT
    val jwt = "abcd123943490rueroifgkjmdfvklmdcxklvmsdklfmdklgnjkfbnvjkdfvnjkdfvncsd"
        .let { SignedJWT.parse(it) }

    // Verify the JWT
    val verified: Boolean = jwt.verify(verifier)
    println("Verified: $verified")
}