package com.odenizturker.auth.entity

import org.springframework.data.relational.core.mapping.Table
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.UUID

@Table("users")
data class UserEntity(
    val id: UUID? = null,
    private val username: String,
    private val password: String,
    private val authorities: List<Authorities>,
    val accountExpired: Boolean,
    val accountLocked: Boolean,
    val credentialsExpired: Boolean,
    val enabled: Boolean,
) : UserDetails {
    override fun getAuthorities(): List<GrantedAuthority> = emptyList()

    override fun getPassword(): String = password

    override fun getUsername(): String = username

    override fun isAccountNonExpired(): Boolean = !accountExpired

    override fun isAccountNonLocked(): Boolean = !accountLocked

    override fun isCredentialsNonExpired(): Boolean = !credentialsExpired
}
