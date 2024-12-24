package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.CartItem;
import org.springframework.stereotype.Service;

@Service
public interface CartItemService {
    CartItem findCartItemById(String id);

}
