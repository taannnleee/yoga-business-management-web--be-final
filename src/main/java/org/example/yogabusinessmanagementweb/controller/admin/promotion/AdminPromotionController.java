package org.example.yogabusinessmanagementweb.controller.admin.promotion;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Promotion;
import org.example.yogabusinessmanagementweb.dto.request.promotion.PromotionRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.service.PromotionService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminPromotionController {
    PromotionService promotionService;
    // Tạo mới promotion
    @PostMapping("/create-promotion")
    public ApiResponse<?> createPromotion(@RequestBody PromotionRequest promotion) {
        Promotion createdPromotion = promotionService.createPromotion(promotion);
        return new ApiResponse<>(HttpStatus.OK.value(), "create promotion success",createdPromotion);

    }
}
