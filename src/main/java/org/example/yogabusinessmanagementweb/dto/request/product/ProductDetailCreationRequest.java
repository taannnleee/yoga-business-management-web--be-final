package org.example.yogabusinessmanagementweb.dto.request.product;

import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProductDetailCreationRequest {
    @NotNull(message = "Description is required")
    String description;
    String color;
    String size;
    String code;
    String brand;
}
