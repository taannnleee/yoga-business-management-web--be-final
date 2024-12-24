package org.example.yogabusinessmanagementweb.dto.request.cart;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CartDeleteRequest {
    @NotNull(message = "Product id is required")
    String productId;
}
