package com.odenizturker.auth.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.odenizturker.auth.entity.ClientEntity
import com.odenizturker.auth.repository.ClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.stereotype.Service
import java.util.UUID
import kotlin.jvm.optionals.getOrNull

@Service
class ClientService(
    private val objectMapper: ObjectMapper,
    private val clientRepository: ClientRepository,
) : RegisteredClientRepository {
    init {
        val oidcClient =
            RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/login/oauth2/code/oidc-client")
                .postLogoutRedirectUri("http://localhost:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build()
        save(oidcClient)
    }

    final override fun save(registeredClient: RegisteredClient) {
        clientRepository.findByClientId(registeredClient.clientId) ?: run {
            clientRepository.save(ClientEntity(registeredClient))
        }
    }

    override fun findById(id: String): RegisteredClient =
        clientRepository.findById(UUID.fromString(id)).getOrNull()?.toRegisteredClient(objectMapper = objectMapper)
            ?: throw IllegalArgumentException("client with id $id not found")

    override fun findByClientId(clientId: String): RegisteredClient =
        clientRepository.findByClientId(clientId)?.toRegisteredClient(objectMapper = objectMapper)
            ?: throw IllegalArgumentException("client with clientId $clientId not found")
}
