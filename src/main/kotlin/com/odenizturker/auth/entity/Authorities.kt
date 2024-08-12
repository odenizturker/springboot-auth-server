package com.odenizturker.auth.entity

import org.springframework.security.core.GrantedAuthority

enum class Authorities : GrantedAuthority {
    USER,
    ADMIN,
    ;

    override fun getAuthority(): String = this.name
}
