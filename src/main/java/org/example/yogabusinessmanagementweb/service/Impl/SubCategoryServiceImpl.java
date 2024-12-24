package org.example.yogabusinessmanagementweb.service.Impl;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.Enum.EStatus;
import org.example.yogabusinessmanagementweb.common.entities.Category;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.common.entities.SubCategory;
import org.example.yogabusinessmanagementweb.common.mapper.Mappers;
import org.example.yogabusinessmanagementweb.common.mapper.SubCategoryMapper;
import org.example.yogabusinessmanagementweb.dto.request.subcategory.SubCategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.subcategory.SubCategoryResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.CategoryRepository;
import org.example.yogabusinessmanagementweb.repositories.SubCategoryRepository;
import org.example.yogabusinessmanagementweb.service.CategoryService;
import org.example.yogabusinessmanagementweb.service.SubCategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class SubCategoryServiceImpl implements SubCategoryService {
    SubCategoryRepository subCategoryRepository;
    CategoryService categoryService;

    CategoryRepository categoryRepository;

    @Autowired
    private SubCategoryMapper subCategoryMapper;



    @Override
    public SubCategoryResponse addSubCategory(SubCategoryCreationRequest subCategoryCreationRequest) {


        Category category = categoryService.findByIdAndStatus(Long.valueOf(subCategoryCreationRequest.getCategoryId()),EStatus.ACTIVE);

        // Chuyển đổi từ DTO sang Entity
        SubCategory subCategory = subCategoryMapper.toSubCategory(subCategoryCreationRequest);
        if (subCategory.getStatus() == null) {
            subCategory.setStatus(EStatus.ACTIVE);
        }
        subCategory.setCategory(category);
        subCategoryRepository.save(subCategory);

        // Chuyển đổi từ Entity sang DTO
        return Mappers.convertToDto(subCategory,SubCategoryResponse.class);
    }

    @Override
    public List<SubCategoryResponse> getSubCategoryOfCategory(String id) {
        Optional<Category> categoryOptional = categoryRepository.findById(Long.valueOf(id));
        if(categoryOptional.isEmpty()) {
            throw  new AppException(ErrorCode.CATEGORY_NOT_FOUND);
        }
        Category category = categoryOptional.get();
        List<SubCategory> list = subCategoryRepository.findAllByCategoryAndStatus(category, EStatus.ACTIVE);

        return Mappers.mapperEntityToDto(list,SubCategoryResponse.class);
    }

    @Override
    public List<SubCategoryResponse> getAllSub() {
        List<SubCategory> list = subCategoryRepository.findAll();
        return Mappers.mapperEntityToDto(list,SubCategoryResponse.class);
    }

    @Override
    public SubCategory getSubCategoryById(String id) {
        Optional<SubCategory> subCategoryOptional = subCategoryRepository.findById(Long.valueOf(id));
        if(subCategoryOptional.isEmpty()) {
            throw  new AppException(ErrorCode.SUBCATEGORY_NOT_FOUND);
        }
        return subCategoryOptional.get();
    }

    @Override
    public void deleteSubCategoryWithStatus(String id) {
        SubCategory sub =  getSubCategoryById(id);
        sub.setStatus(EStatus.INACTIVE);
        for(Product product : sub.getProducts()) {
            product.setStatus(false);
        }
        subCategoryRepository.save(sub);
    }

}
