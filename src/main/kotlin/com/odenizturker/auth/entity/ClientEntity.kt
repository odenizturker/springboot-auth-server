package com.odenizturker.auth.entity

import com.odenizturker.auth.model.AuthenticationMethod
import com.odenizturker.auth.model.GrantType
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import java.time.Instant
import java.util.UUID

@Table("clients")
data class ClientEntity(
    @Id
    val id: UUID? = null,
    val clientId: String,
    val clientIdIssuedAt: Instant?,
    val clientSecret: String?,
    val clientSecretExpiresAt: Instant?,
    val clientName: String,
    val clientAuthenticationMethods: Set<AuthenticationMethod>,
    val authorizationGrantTypes: Set<GrantType>,
    val redirectUris: Set<String>,
    val postLogoutRedirectUris: Set<String>,
    val scopes: Set<String>,
    val clientSettings: String,
    val tokenSettings: String,
) {
    constructor(client: RegisteredClient) : this(
        clientId = client.clientId,
        clientIdIssuedAt = client.clientIdIssuedAt,
        clientSecret = client.clientSecret,
        clientSecretExpiresAt = client.clientSecretExpiresAt,
        clientName = client.clientName,
        clientAuthenticationMethods = AuthenticationMethod.from(client.clientAuthenticationMethods),
        authorizationGrantTypes = GrantType.from(client.authorizationGrantTypes),
        redirectUris = client.redirectUris,
        postLogoutRedirectUris = client.postLogoutRedirectUris,
        scopes = client.scopes,
        clientSettings = client.clientSettings.settings.toString(),
        tokenSettings = client.tokenSettings.settings.toString(),
    )

    fun toRegisteredClient(): RegisteredClient =
        RegisteredClient
            .withId(id.toString())
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethods {
                it.addAll(clientAuthenticationMethods.map { ClientAuthenticationMethod(it.value) })
            }.authorizationGrantTypes {
                it.addAll(authorizationGrantTypes.map { AuthorizationGrantType(it.value) })
            }.redirectUris { it.addAll(redirectUris) }
            .postLogoutRedirectUris { it.addAll(postLogoutRedirectUris) }
            .scopes { it.addAll(scopes) }
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build()
}
