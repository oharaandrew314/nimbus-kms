package dev.aohara.nimbuskms

import com.nimbusds.jose.RemoteKeySourceException
import dev.forkhandles.result4k.Result4k
import dev.forkhandles.result4k.onFailure
import org.http4k.connect.RemoteFailure

fun <R: Any> Result4k<R, RemoteFailure>.valueOrThrow(): R = onFailure { throw RemoteKeySourceException(it.reason.message, null) }