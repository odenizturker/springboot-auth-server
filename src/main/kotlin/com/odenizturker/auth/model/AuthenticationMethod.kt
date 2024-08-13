package com.odenizturker.auth.model

import org.springframework.security.oauth2.core.ClientAuthenticationMethod

enum class AuthenticationMethod(
    val value: String,
) {
    CLIENT_SECRET_BASIC("client_secret_basic"),
    CLIENT_SECRET_POST("client_secret_post"),
    CLIENT_SECRET_JWT("client_secret_jwt"),
    PRIVATE_KEY_JWT("private_key_jwt"),
    NONE("none"),
    TLS_CLIENT_AUTH("tls_client_auth"),
    SELF_SIGNED_TLS_CLIENT_AUTH("self_signed_tls_client_auth"), ;

    companion object {
        fun from(clientAuthenticationMethods: Set<ClientAuthenticationMethod>): Set<AuthenticationMethod> =
            clientAuthenticationMethods
                .map { clientAuthenticationMethod ->
                    entries.first { it.value == clientAuthenticationMethod.value }
                }.toSet()
    }
}
