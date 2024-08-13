package com.odenizturker.auth.service

import com.odenizturker.auth.entity.UserEntity
import com.odenizturker.auth.model.UserRegistrationModel
import com.odenizturker.auth.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
) : UserDetailsService {
    fun create(user: UserRegistrationModel) {
        userRepository.findByUsername(user.username) ?: run {
            userRepository.save(
                UserEntity(
                    username = user.username,
                    password = passwordEncoder.encode(user.password),
                    authorities = emptySet(),
                ),
            )
        }
    }

    override fun loadUserByUsername(username: String): UserDetails =
        userRepository.findByUsername(username) ?: throw UsernameNotFoundException("User $username not found")
}
