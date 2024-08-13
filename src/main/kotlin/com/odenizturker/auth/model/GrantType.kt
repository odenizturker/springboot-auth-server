package com.odenizturker.auth.model

import org.springframework.security.oauth2.core.AuthorizationGrantType

enum class GrantType(
    val value: String,
) {
    AUTHORIZATION_CODE("authorization_code"),
    REFRESH_TOKEN("refresh_token"),
    CLIENT_CREDENTIALS("client_credentials"), ;

    companion object {
        fun from(authorizationGrantTypes: Set<AuthorizationGrantType>): Set<GrantType> =
            authorizationGrantTypes
                .map { authorizationGrantType ->
                    GrantType.entries.first { it.value == authorizationGrantType.value }
                }.toSet()
    }
}
