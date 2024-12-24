package org.example.yogabusinessmanagementweb.dto.request.promotion;

import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EDiscountType;

import java.util.Date;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class PromotionRequest {
    String code;

    Double discount; // Giá trị giảm giá, có thể là phần trăm hoặc số tiền

    String discountType;

    int usage_limit;

    int used_count;

    Date startDate;

    Date expiryDate;

    Boolean isActive;

}
