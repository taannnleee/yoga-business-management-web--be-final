package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.CartItem;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartItemCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;

import org.example.yogabusinessmanagementweb.dto.response.cart.CartItemResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface CartItemMapper {
    @Mapping(target = "product.subCategory", ignore = true)
    CartItemResponse toCartItemResponse(CartItem cartItem);
    CartItem toCartItem(CartItemCreationRequest cartItemCreationRequest);

}
