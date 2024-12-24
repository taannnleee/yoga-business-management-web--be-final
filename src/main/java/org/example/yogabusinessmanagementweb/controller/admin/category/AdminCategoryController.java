package org.example.yogabusinessmanagementweb.controller.admin.category;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.category.CategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponseAndQuantityProduct;
import org.example.yogabusinessmanagementweb.service.CategoryService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminCategoryController {
    CategoryService categoryService;

    @PostMapping("/add-category")
    public ApiResponse<?> createCategory(@Valid @RequestBody CategoryCreationRequest categoryCreationRequest) {
        CategoryResponse addCategoryResponse = categoryService.addCategory(categoryCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "create category  successfully",addCategoryResponse);
    }

    @GetMapping("/get-all-category")
    public ApiResponse<?> getAllCategory() {
        List<CategoryResponse> list = categoryService.getAllCategory();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all category  successfully",list);
    }
    @GetMapping("/get-all-category-and-quantity-product")
    public ApiResponse<?> getAllCategoryAndQuantityProduct() {
        List<CategoryResponseAndQuantityProduct> list = categoryService.getAllCategoryAndQuantityProduct();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all category and quantity product successfully",list);
    }

    @GetMapping("/delete-status-category/{id}")
    public ApiResponse<?> deleteCategoryWithStatus(@Valid @PathVariable String id){
        try{
            categoryService.deleteCategoryWithStatus(id);
            return new ApiResponse<>(HttpStatus.OK.value(), "delete category successfully");
        }catch (Exception e){
            return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),e.getMessage());
        }
    }
}
