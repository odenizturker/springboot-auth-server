package com.odenizturker.auth.repository

import com.odenizturker.auth.entity.UserEntity
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository
import java.util.UUID

@Repository
interface UserRepository : CrudRepository<UserEntity, UUID> {
    fun findByUsername(username: String): UserEntity?
}
