package org.example.yogabusinessmanagementweb.dto.response.order;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EPaymentStatus;
import org.example.yogabusinessmanagementweb.dto.response.orderItem.OrderItemResponse;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class OrderResponse {
    Long id;
    int totalItem;
    BigDecimal totalPrice;
    String eStatusOrder;
    String createdBy;
    Date updatedAt;
    Date createdAt;
    String paymentMethod;
    EPaymentStatus  ePaymentStatus;



}
