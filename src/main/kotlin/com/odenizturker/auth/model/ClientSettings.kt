package com.odenizturker.auth.model

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings as CS

data class ClientSettings(
    val requireProofKey: Boolean,
    val requireAuthorizationConsent: Boolean,
    val jwkSetUrl: String?,
    val tokenEndpointAuthenticationSigningAlgorithm: JwsAlgorithm?,
    val x509CertificateSubjectDN: String?,
) {
    constructor(client: CS) : this(
        requireProofKey = client.isRequireProofKey,
        requireAuthorizationConsent = client.isRequireAuthorizationConsent,
        jwkSetUrl = client.jwkSetUrl,
        tokenEndpointAuthenticationSigningAlgorithm = client.tokenEndpointAuthenticationSigningAlgorithm,
        x509CertificateSubjectDN = client.x509CertificateSubjectDN,
    )

    fun toMap(objectMapper: ObjectMapper): Map<String, Any> = objectMapper.convertValue(this, object : TypeReference<Map<String, Any>>() {})
}
