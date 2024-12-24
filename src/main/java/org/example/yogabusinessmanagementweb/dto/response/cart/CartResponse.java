package org.example.yogabusinessmanagementweb.dto.response.cart;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.util.List;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CartResponse {
    Long id;
    int totalItem;
    BigDecimal totalPrice;
    List<CartItemResponse> cartItem;



}
