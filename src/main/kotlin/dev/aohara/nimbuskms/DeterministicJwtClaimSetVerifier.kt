package dev.aohara.nimbuskms

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import java.time.Clock
import java.util.Date

open class DeterministicJwtClaimSetVerifier(
    private val clock: Clock,
    exactMatchClaims: JWTClaimsSet = JWTClaimsSet.Builder().build(),
    requiredClaims: Set<String> = emptySet(),
) : DefaultJWTClaimsVerifier<SecurityContext>(exactMatchClaims, requiredClaims) {
    override fun currentTime(): Date = Date.from(clock.instant())
}