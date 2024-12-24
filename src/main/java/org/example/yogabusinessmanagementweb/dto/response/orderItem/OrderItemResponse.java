package org.example.yogabusinessmanagementweb.dto.response.orderItem;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;

import java.math.BigDecimal;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class OrderItemResponse {
    int quantity;
    BigDecimal totalPrice;
    ProductResponse product;
}
