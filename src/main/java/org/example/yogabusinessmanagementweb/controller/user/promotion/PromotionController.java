package org.example.yogabusinessmanagementweb.controller.user.promotion;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Promotion;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.service.PromotionService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/promotion")
@Slf4j
public class PromotionController {
    PromotionService promotionService;
    @GetMapping("/get-four-big-promotion")
    public ApiResponse<?> getFourBigPromotion() {
        List<Promotion> promotionList =  promotionService.getFourBigPromotion();
        return new ApiResponse<>(HttpStatus.OK.value(), "get four big promotion success",promotionList);
    }
}
