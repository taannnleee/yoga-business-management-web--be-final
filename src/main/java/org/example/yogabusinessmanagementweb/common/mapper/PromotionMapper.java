package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.Enum.EDiscountType;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.Promotion;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.request.promotion.PromotionRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface PromotionMapper {
//    AddressResponse toAddressResponse(Address address);
// Mapping từ PromotionRequest sang Promotion entity
@Mapping(target = "eDiscountType", expression = "java(mapDiscountType(promotionRequest.getDiscountType()))")
Promotion toPromotion(PromotionRequest promotionRequest);

    // Phương thức phụ để chuyển discountType từ String sang EDiscountType enum
    default EDiscountType mapDiscountType(String discountType) {
        if (discountType == null) {
            return null; // Xử lý trường hợp null nếu cần
        }
        // Giả sử discountType là một giá trị chuỗi trùng với tên của hằng số enum
        try {
            return EDiscountType.valueOf(discountType.toUpperCase());
        } catch (IllegalArgumentException e) {
            // Log lỗi hoặc xử lý trường hợp chuỗi không khớp với hằng số enum
            return null; // Bạn có thể thay đổi trả về giá trị mặc định thay vì null
        }
    }
//    void updateAddress(@MappingTarget Address address, AddressRequest addressRequest );
}
