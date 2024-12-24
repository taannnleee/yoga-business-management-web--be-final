package org.example.yogabusinessmanagementweb.dto.request.product;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductDetailResponse;

import java.math.BigDecimal;
import java.util.Map;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProductCreationRequest {
    @NotNull(message = "Title is required")
    String title;
    @NotNull(message = "Sub Category Id is required")
    Long subCategoryId;
    String imagePath;
    @NotNull(message = "Price in Product is required")
    BigDecimal price;
    Double averageRating = 0.0;
    Double sold = 0.0;
//    String code;
    String brand;
    String description;
    Map<String, Map<String, String>> variants;

}
