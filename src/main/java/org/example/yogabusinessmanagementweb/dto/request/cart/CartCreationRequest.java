package org.example.yogabusinessmanagementweb.dto.request.cart;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.util.Map;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CartCreationRequest {
    @NotNull(message = "Product id is required")
    String productId;

    @NotNull(message = "Quantity id is required")
    int quantity;

    Map<String, Map<String, String>>  currentVariant;


}
