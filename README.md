[![codecov](https://codecov.io/gh/oharaandrew314/nimbus-kms/graph/badge.svg?token=BD9IMCS79H)](https://codecov.io/gh/oharaandrew314/nimbus-kms)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maven Central Version](https://img.shields.io/maven-central/v/dev.andrewohara/nimbus-kms)](https://central.sonatype.com/artifact/dev.andrewohara/nimbus-kms)

# Nimbus KMS

Want to sign and verify JWTs without worrying about provisioning and guarding sensitive private keys?
This plugin for Nimbus JOSE+JWT will let you use Amazon KMS to do all the heavy lifting for you.

The Amazon KMS communication is done with the featherweight and reflectionless, [http4k-connect](https://github.com/http4k/http4k-connect);
making it well suited to serverless environments, and offers unreasonable testability.

## Requirements

Java 11, 17, and 21 are officially supported.

## Quickstart

```kotlin
// Build KMS client and provide the key id
val kms = KMS.Http()
val kmsKeyId = KMSKeyId.of("my_kms_key_id")
```

To sign a JWT

```kotlin
val jwsSigner = KmsJwsSigner(kms, kmsKeyId)

// Choose a signing algorithm.  Must be supported by your key!
val algorithm = JWSAlgorithm.RS256

// Build JWT
val claims = JWTClaimsSet.Builder().subject("user1").build()
val header = JWSHeader.Builder(algorithm).build()
val jwt = SignedJWT(header, claims).apply {
    sign(jwsSigner)
}

println(jwt.serialize())
```

To verify a JWT

```kotlin
// parse the JWT
val jwt = SignedJWT.parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJpc3MiLCJpYXQiOm51bGwsImV4cCI6bnVsbCwiYXVkIjoiIiwic3ViIjoic3ViIn0.zPOJpY-vt7eHjNqQN0tuytWkyP02XJVnf_5vkzeFeb0")

// Verify the JWT
val verifier = KmsJwsVerifier(kms, kmsKeyId)
val verified: Boolean = jwt.verify(verifier)
println("Verified: $verified")
```

## Public Key Verification

It may be faster and cheaper to verify JWTs locally using the KMS Key's public key.
This library provides a `JWSKeySelector` that will download a parse the public key from Amazon KMS.
You can then use it like any other javax crypto `PublicKey`.

```kotlin
val selector = KmsPublicKeyJwsKeySelector<SecurityContext>(kms, keyId)
val publicKey: PublicKey = selector.selectJWSKeys(null, null).first()

val verifier = RSASSAVerifier(publicKey)

val jwt = SignedJWT.parse("abcdefgh123456")
jwt.verify(verifier) shouldBe true
```
:warning: Verifying an EC signature locally requires BouncyCastle.

```kotlin
val verifier = ECDSAVerifier(publicKey).apply {
    jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
}
jwt.verify(verifier) shouldBe true
```


## Using the JWT Processor

Using a JWT Processor makes it easy to perform all the optional checks: like subject, issuer, claims, and expiration.

```kotlin
val exactClaims = JWTClaimsSet.Builder()
    .issuer("iss")
    .build()

val requiredClaims = setOf("subject")

val processor = DefaultJWTProcessor<SecurityContext>().apply {
    jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(exactClaims, requiredClaims) // verify claims
    jwsVerifierFactory = KmsJwsVerifierFactory(kms) // Use KMS to verify JWTs
    jwsKeySelector = KmsJwsKeySelector(key1) // select a specific KMS key
}

val jwt = SignedJWT.parse("abcdefgh123456")
val claims = processor.process(jwt, null)
println(claims.subject)
```

You can also use it to verify JWTs locally

```kotlin
val processor = DefaultJWTProcessor<SecurityContext>().apply {
    jwsKeySelector = KmsPublicKeyJwsKeySelector( // download the KMS public key
        kms, key1, // select a specific KMS key
        BouncyCastleProviderSingleton.getInstance() // required for EC keys
    )
    // use the default cryptographic verifier
    jwsVerifierFactory.jcaContext.provider = BouncyCastleProviderSingleton.getInstance() // required for EC keys
}

val jwt = SignedJWT.parse("abcdefgh123456")
val claims = processor.process(jwt, null)
println(claims.subject)
```

## Test Support

This plugin's Amazon KMS communication is built on [http4k-connect](https://github.com/http4k/http4k-connect),
which provides an unreasonable level of testability.

Just add the fake KMS library

```kotlin
// build.gradle.kts
testImplementation("org.http4k:http4k-connect-amazon-kms-fake")
```

```kotlin
class MyTest {
    // start an in-memory fake KMS server
    private val kms = FakeKms().client()

    // use fake KMS to create a key
    private val keyId = kms.createKey(CustomerMasterKeySpec.RSA_2048, KeyUsage.SIGN_VERIFY)
        .shouldBeSuccess()
        .KeyMetadata.KeyId

    // use fake KMS to sign a JWT
    private fun signJwt(subject: String): SignedJwt {
        val claimsSet = JWTClaimsSet.Builder()
            .subject(subject)
            .build()

        val header = JWSHeader.Builder(alg).build()

        val signer = KmsJwsSigner(kms, keyId)
        return SignedJWT(header, claimsSet).apply {
            sign(signer)
        }
    }

    @Test
    fun `make authorized service call`() {
        val jwt = signJwt("user1")

        // Your app will use the injected fake KMS to verify JWTs
        val myApp = createMyApp(
            kmsClient = kms,
            kmsKeyId = keyId
        )

        // make a full service call to your app
        myApp.getProfile(jwt).name shouldBe "User One"
    }
}
```
