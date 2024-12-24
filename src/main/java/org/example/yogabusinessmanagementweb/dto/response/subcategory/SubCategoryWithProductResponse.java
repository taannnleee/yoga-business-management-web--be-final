package org.example.yogabusinessmanagementweb.dto.response.subcategory;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;

import java.util.List;
@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class SubCategoryWithProductResponse {
    Long id;
    String name;
    List<ProductResponse> products;
}
