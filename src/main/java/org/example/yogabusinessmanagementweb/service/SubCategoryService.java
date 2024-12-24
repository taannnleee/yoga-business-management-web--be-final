package org.example.yogabusinessmanagementweb.service;

import jakarta.validation.Valid;
import org.example.yogabusinessmanagementweb.common.entities.SubCategory;
import org.example.yogabusinessmanagementweb.dto.request.subcategory.SubCategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.subcategory.SubCategoryResponse;

import java.util.List;

public interface SubCategoryService {
    SubCategoryResponse addSubCategory(SubCategoryCreationRequest subCategoryCreationRequest);

    List<SubCategoryResponse> getSubCategoryOfCategory(String id);

    List<SubCategoryResponse> getAllSub();

    SubCategory getSubCategoryById(String id);

    void deleteSubCategoryWithStatus(@Valid String id);
}
