package org.example.yogabusinessmanagementweb.controller.admin.subcategory;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.subcategory.SubCategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.example.yogabusinessmanagementweb.dto.response.subcategory.SubCategoryResponse;
import org.example.yogabusinessmanagementweb.service.SubCategoryService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminSubcategoryController {
    SubCategoryService subCategoryService;

    @PostMapping("/add-subcategory")
    public ApiResponse<?> createSubCategory(@Valid @RequestBody SubCategoryCreationRequest subCategoryCreationRequest) {
        SubCategoryResponse subcategoryResponse = subCategoryService.addSubCategory(subCategoryCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "create subcategory  successfully",subcategoryResponse);
    }

    @GetMapping("/get-all-subcategory-of-category/{id}")
    public ApiResponse<?> getSubCategoryOfCategory(@PathVariable String id) {
        List<SubCategoryResponse> list = subCategoryService.getSubCategoryOfCategory(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get all subcategory of category  successfully",list);
    }
    @GetMapping("/get-all-subcategory")
    public ApiResponse<?> getSubCategoryOfCategory() {
        List<SubCategoryResponse> list = subCategoryService.getAllSub();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all subcategory successfully",list);
    }

    @GetMapping("/delete-status-sub-category/{id}")
    public ApiResponse<?> deleteSubCategoryWithStatus(@Valid @PathVariable String id){
        try{
            subCategoryService.deleteSubCategoryWithStatus(id);
            return new ApiResponse<>(HttpStatus.OK.value(), "delete subcategory successfully");
        }catch (Exception e){
            return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),e.getMessage());
        }
    }
}
