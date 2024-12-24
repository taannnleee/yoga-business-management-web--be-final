package org.example.yogabusinessmanagementweb.service.Impl;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.CartItem;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.CartItemRepository;
import org.example.yogabusinessmanagementweb.repositories.CartRepository;
import org.example.yogabusinessmanagementweb.service.CartItemService;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class CartItemServiceImpl implements CartItemService {
    CartItemRepository cartItemRepository;
    @Override
    public CartItem findCartItemById(String id){
        Optional<CartItem> itemOptional =  cartItemRepository.findById(Long.valueOf(id));
         if(itemOptional.isEmpty()){
             throw new AppException(ErrorCode.CART_ITEM_NOT_FOUND);
         }
         return itemOptional.get();
    }
}
