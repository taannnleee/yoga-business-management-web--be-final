package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.Promotion;
import org.example.yogabusinessmanagementweb.dto.request.promotion.PromotionRequest;

import java.util.List;

public interface PromotionService {
    Promotion createPromotion(PromotionRequest promotion);

    List<Promotion> getFourBigPromotion();
}
