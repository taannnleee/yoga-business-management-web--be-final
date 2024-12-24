package org.example.yogabusinessmanagementweb.dto.response.category;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.subcategory.SubCategoryResponse;
import org.example.yogabusinessmanagementweb.dto.response.subcategory.SubCategoryWithProductResponse;

import java.util.List;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CategoryWithProductResponse {
    Long id;
    String name;
    String urlImage;
    List<SubCategoryWithProductResponse> subCategories;
}
