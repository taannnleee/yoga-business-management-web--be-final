package org.example.yogabusinessmanagementweb.dto.request.order;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.dto.response.checkout.UserAddressDefaultResponse;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class OrderCreationRequest {
    String addressId;
    String paymentMethod;
    BigDecimal totalPricePromotion;
    String promotionId;

//    Map<String, Map<String, String>>  currentVariant;
//    List<Product> products;
//    BigDecimal totalPrice;
}
