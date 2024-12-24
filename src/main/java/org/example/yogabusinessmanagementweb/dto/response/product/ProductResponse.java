package org.example.yogabusinessmanagementweb.dto.response.product;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.SubCategory;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.subcategory.SubCategoryResponse;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Data
@RequiredArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProductResponse {
    Long id;
    String imagePath;
    String status;
    BigDecimal price;
    String title;
    SubCategoryResponse subCategory;
    String code;
    String brand;
    String description;
    Double averageRating;
    List<CommentResponse> comments;
    Map<String, Map<String, String>> variants;
}
