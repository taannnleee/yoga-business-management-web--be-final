package org.example.yogabusinessmanagementweb.dto.response.cart;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;

import java.math.BigDecimal;
import java.util.Map;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CartItemResponse {
    Long id;
    int quantity;
    BigDecimal totalPrice;
    ProductResponse product;
    Map<String, Map<String, String>>  currentVariant;
}
