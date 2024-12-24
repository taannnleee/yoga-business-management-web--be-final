package org.example.yogabusinessmanagementweb.service;

import jakarta.servlet.http.HttpServletRequest;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.entities.Wishlist;
import org.example.yogabusinessmanagementweb.dto.request.wishlist.WishListRequest;

import java.util.List;

public interface WishlistService {
    Wishlist findById(String id);
    void addWishlist(HttpServletRequest request, WishListRequest wishListRequest ) ;

    List<Wishlist> getWishlistOfUser(HttpServletRequest request);
    List<Wishlist> findByUser(User user);

    Wishlist deleteWishlistOfUser(HttpServletRequest request, String wishlistId);

    Wishlist getWishlistExists(HttpServletRequest request,WishListRequest wishListRequest);

    Wishlist deleteWishlistByProductId(HttpServletRequest request, String productId);
}
