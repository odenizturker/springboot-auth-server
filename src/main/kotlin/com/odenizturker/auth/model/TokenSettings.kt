package com.odenizturker.auth.model

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Duration
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings as TS

data class TokenSettings(
    val reuseRefreshTokens: Boolean,
    val x509CertificateBoundAccessTokens: Boolean,
    val accessTokenFormat: OAuth2TokenFormat,
    val accessTokenTimeToLive: Duration,
    val authorizationCodeTimeToLive: Duration,
    val deviceCodeTimeToLive: Duration,
    val idTokenSignatureAlgorithm: SignatureAlgorithm,
    val refreshTokenTimeToLive: Duration,
) {
    constructor(token: TS) : this(
        reuseRefreshTokens = token.isReuseRefreshTokens,
        x509CertificateBoundAccessTokens = token.isX509CertificateBoundAccessTokens,
        accessTokenFormat = token.accessTokenFormat,
        accessTokenTimeToLive = token.accessTokenTimeToLive,
        authorizationCodeTimeToLive = token.authorizationCodeTimeToLive,
        deviceCodeTimeToLive = token.deviceCodeTimeToLive,
        idTokenSignatureAlgorithm = token.idTokenSignatureAlgorithm,
        refreshTokenTimeToLive = token.refreshTokenTimeToLive,
    )

    fun toMap(objectMapper: ObjectMapper): Map<String, Any> = objectMapper.convertValue(this, object : TypeReference<Map<String, Any>>() {})
}
