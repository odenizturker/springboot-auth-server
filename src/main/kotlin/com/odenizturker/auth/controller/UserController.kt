package com.odenizturker.auth.controller

import com.odenizturker.auth.model.UserRegistrationModel
import com.odenizturker.auth.service.UserService
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController(
    private val userService: UserService,
) {
    @PostMapping
    fun register(
        @RequestBody userRegistrationModel: UserRegistrationModel,
    ) = userService.create(userRegistrationModel)
}
