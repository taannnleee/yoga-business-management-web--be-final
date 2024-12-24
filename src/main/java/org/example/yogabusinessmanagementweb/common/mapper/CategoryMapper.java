package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.entities.Category;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryWithProductResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring", uses = {SubCategoryMapper.class})
public interface CategoryMapper {

    @Mapping(target = "subCategories", source = "subCategories")
    CategoryWithProductResponse toCategoryWithProductResponse(Category category);
}
