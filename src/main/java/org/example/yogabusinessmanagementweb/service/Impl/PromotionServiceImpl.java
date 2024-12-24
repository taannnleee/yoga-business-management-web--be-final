package org.example.yogabusinessmanagementweb.service.Impl;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Promotion;
import org.example.yogabusinessmanagementweb.common.mapper.PromotionMapper;
import org.example.yogabusinessmanagementweb.dto.request.promotion.PromotionRequest;
import org.example.yogabusinessmanagementweb.repositories.PromotionRepository;
import org.example.yogabusinessmanagementweb.service.PromotionService;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class PromotionServiceImpl implements PromotionService {
    PromotionRepository promotionRepository;
    PromotionMapper promotionMapper;
    @Override
    // Hàm tạo mới promotion
    public Promotion createPromotion(PromotionRequest promotionRequest) {
        Promotion promotion =  promotionMapper.toPromotion(promotionRequest);
        // Kiểm tra giá trị đầu vào
        if (promotion.getDiscount() <= 0) {
            throw new IllegalArgumentException("Discount value must be greater than 0.");
        }
        if (promotion.getStartDate().after(promotion.getExpiryDate())) {
            throw new IllegalArgumentException("Start date cannot be after expiry date.");
        }

        // Thiết lập mặc định cho các trường khác (nếu cần)
        promotion.setUsed_count(0);

        // Lưu vào cơ sở dữ liệu
        return promotionRepository.save(promotion);

    }

    @Override
    public List<Promotion> getFourBigPromotion() {
        return promotionRepository.findTop4ByDiscount();

    }
}
