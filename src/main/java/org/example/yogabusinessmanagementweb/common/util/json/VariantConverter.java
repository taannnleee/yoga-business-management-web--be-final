package org.example.yogabusinessmanagementweb.common.util.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class VariantConverter implements AttributeConverter<Variant, String> {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(Variant attribute) {
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public Variant convertToEntityAttribute(String dbData) {
        try {
            return objectMapper.readValue(dbData, Variant.class);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

