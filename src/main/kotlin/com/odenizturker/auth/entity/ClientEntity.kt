package com.odenizturker.auth.entity

import com.fasterxml.jackson.databind.ObjectMapper
import com.odenizturker.auth.model.AuthenticationMethod
import com.odenizturker.auth.model.ClientSettings
import com.odenizturker.auth.model.GrantType
import com.odenizturker.auth.model.TokenSettings
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import java.io.Serializable
import java.time.Instant
import java.util.UUID
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings as CS
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings as TS

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
    val clientSettings: ClientSettings,
    val tokenSettings: TokenSettings,
) : Serializable {
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
        clientSettings = ClientSettings(client.clientSettings),
        tokenSettings = TokenSettings(client.tokenSettings),
    )

    fun toRegisteredClient(objectMapper: ObjectMapper): RegisteredClient =
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
            .clientSettings(CS.withSettings(clientSettings.toMap(objectMapper = objectMapper)).build())
            .tokenSettings(TS.withSettings(tokenSettings.toMap(objectMapper = objectMapper)).build())
            .build()
}
