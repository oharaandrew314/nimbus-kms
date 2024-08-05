package dev.aohara.nimbuskms.examples

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import dev.aohara.nimbuskms.KmsPublicKeyJwsKeySelector
import org.http4k.connect.amazon.core.model.KMSKeyId
import org.http4k.connect.amazon.kms.Http
import org.http4k.connect.amazon.kms.KMS

fun main() {
    val kms = KMS.Http()
    val kmsKeyId = KMSKeyId.of("your_key_id")

    // to verify with the KMS public key, the provided key selector simplifies the process
    val processor = DefaultJWTProcessor<SecurityContext>().apply {
        jwsKeySelector = KmsPublicKeyJwsKeySelector(kms, kmsKeyId)
    }

    // parse the JWT
    val jwt = "abcd123943490rueroifgkjmdfvklmdcxklvmsdklfmdklgnjkfbnvjkdfvnjkdfvncsd"
        .let { SignedJWT.parse(it) }

    // verify the JWT
    val claims = processor.process(jwt, null)
    println(claims.subject)
}