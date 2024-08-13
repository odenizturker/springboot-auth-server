package com.odenizturker.auth.util

import com.fasterxml.jackson.databind.ObjectMapper
import com.odenizturker.auth.model.TokenSettings
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter

@WritingConverter
class TokenSettingsWritingConverter(
    private val objectMapper: ObjectMapper,
) : Converter<TokenSettings, String> {
    override fun convert(source: TokenSettings): String = objectMapper.writeValueAsString(source)
}

@ReadingConverter
class TokenSettingsReadingConverter(
    private val objectMapper: ObjectMapper,
) : Converter<String, TokenSettings> {
    override fun convert(source: String): TokenSettings = objectMapper.readValue(source, TokenSettings::class.java)
}
