package com.odenizturker.auth.repository

import com.odenizturker.auth.entity.ClientEntity
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository
import java.util.UUID

@Repository
interface ClientRepository : CrudRepository<ClientEntity, UUID> {
    fun findByClientId(clientId: String): ClientEntity?
}
