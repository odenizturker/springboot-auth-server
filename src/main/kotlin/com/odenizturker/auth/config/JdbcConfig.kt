package com.odenizturker.auth.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.odenizturker.auth.util.ClientSettingsReadingConverter
import com.odenizturker.auth.util.ClientSettingsWritingConverter
import com.odenizturker.auth.util.TokenSettingsReadingConverter
import com.odenizturker.auth.util.TokenSettingsWritingConverter
import org.springframework.context.annotation.Configuration
import org.springframework.data.jdbc.repository.config.AbstractJdbcConfiguration

@Configuration
class JdbcConfig(
    private val objectMapper: ObjectMapper,
) : AbstractJdbcConfiguration() {
    override fun userConverters(): List<*> =
        listOf(
            ClientSettingsReadingConverter(objectMapper),
            ClientSettingsWritingConverter(objectMapper),
            TokenSettingsReadingConverter(objectMapper),
            TokenSettingsWritingConverter(objectMapper),
        )
}
