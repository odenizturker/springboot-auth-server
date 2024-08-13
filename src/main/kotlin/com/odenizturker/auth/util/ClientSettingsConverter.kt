package com.odenizturker.auth.util

import com.fasterxml.jackson.databind.ObjectMapper
import com.odenizturker.auth.model.ClientSettings
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter

@WritingConverter
class ClientSettingsWritingConverter(
    private val objectMapper: ObjectMapper,
) : Converter<ClientSettings, String> {
    override fun convert(source: ClientSettings): String = objectMapper.writeValueAsString(source)
}

@ReadingConverter
class ClientSettingsReadingConverter(
    private val objectMapper: ObjectMapper,
) : Converter<String, ClientSettings> {
    override fun convert(source: String): ClientSettings = objectMapper.readValue(source, ClientSettings::class.java)
}
