package org.example.yogabusinessmanagementweb.controller.user.category;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Category;
import org.example.yogabusinessmanagementweb.dto.request.category.CategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryUserResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryWithProductResponse;
import org.example.yogabusinessmanagementweb.service.CategoryService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/category")
@Slf4j
public class CategoryController {
    CategoryService categoryService;

//    @GetMapping("/get-all-category")
//    public ApiResponse<?> getAllCategory() {
//        List<CategoryUserResponse> list = categoryService.getAllCategoryByUser();
//        return new ApiResponse<>(HttpStatus.OK.value(), "get all category by user successfully",list);
//    }
    @GetMapping("/with-products")
    public ApiResponse<List<CategoryWithProductResponse>> getCategoriesWithProducts() {
        List<CategoryWithProductResponse> list = categoryService.getCategoriesWithProducts();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all category successfully",list);
    }
    @GetMapping("/with-sub-categories")
    public ApiResponse<?> getAllCategory() {
        List<CategoryResponse> list = categoryService.getAllCategory();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all category with subcategory successfully",list);
    }
}
