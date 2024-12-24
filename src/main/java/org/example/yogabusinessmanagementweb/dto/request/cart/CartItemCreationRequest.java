package org.example.yogabusinessmanagementweb.dto.request.cart;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CartItemCreationRequest {
    String id;

    String productId;
    int quantity;

}
