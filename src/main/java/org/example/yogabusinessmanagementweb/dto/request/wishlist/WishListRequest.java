package org.example.yogabusinessmanagementweb.dto.request.wishlist;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class WishListRequest {
    Long productId;
}
