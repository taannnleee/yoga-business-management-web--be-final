package org.example.yogabusinessmanagementweb.dto.response.category;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CategoryUserResponse {
    Long id;
    String name;
    String status;
}
