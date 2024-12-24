package org.example.yogabusinessmanagementweb.service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.entities.Wishlist;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.wishlist.WishListRequest;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.WishlistRepository;
import org.example.yogabusinessmanagementweb.service.ProductService;
import org.example.yogabusinessmanagementweb.service.WishlistService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class WishlistServiceImpl implements WishlistService {
    WishlistRepository wishlistRepository;
    JwtUtil jwtUtil;
    ProductService productService;
    @Override
    public void addWishlist(HttpServletRequest request, WishListRequest wishListRequest )  {
        Wishlist wishlist = new Wishlist();
        User user =  jwtUtil.getUserFromRequest(request);
        Product product =  productService.getProductById(String.valueOf(wishListRequest.getProductId()));
        wishlist.setProduct(product);
        wishlist.setUser(user);

        Wishlist wishlistExist = wishlistRepository.findByProductIdAndUserId(product.getId(), user.getId());
        if(wishlistExist != null ) {
            throw  new AppException(ErrorCode.PRODUCT_EXISTS_WISHLIST);
        }
        wishlistRepository.save(wishlist);
    }

    @Override
    public List<Wishlist> getWishlistOfUser(HttpServletRequest request) {
        User user  = jwtUtil.getUserFromRequest(request);
        List<Wishlist> wishlist =  findByUser(user);
        return wishlist;

    }

    @Override
    public Wishlist findById(String id) {
        Wishlist wishlist = wishlistRepository.findById(Long.valueOf(id)).orElseThrow(
                () -> new AppException(ErrorCode.WISHLIST_NOT_FOUND)
        );
        return wishlist;
    }

    @Override
    public List<Wishlist> findByUser(User user) {
        List<Wishlist> wishlist =  wishlistRepository.findByUser(user);

        return wishlist;
    }

    @Override
    public Wishlist deleteWishlistOfUser(HttpServletRequest request, String wishlistId) {
        Wishlist wishlist =  wishlistRepository.findById(Long.valueOf(wishlistId)).orElseThrow(
                () -> new AppException(ErrorCode.WISHLIST_NOT_FOUND));

        wishlistRepository.deleteById(wishlist.getId());
        return wishlist;
    }

    @Override
    public Wishlist getWishlistExists(HttpServletRequest request,WishListRequest wishListRequest) {
        User user  = jwtUtil.getUserFromRequest(request);
        Wishlist wishlist  =  wishlistRepository.findByProductIdAndUserId(wishListRequest.getProductId(), user.getId());
        if(wishlist == null) {
            throw  new AppException(ErrorCode.WISHLIST_NOT_FOUND);
        }
        return wishlist;
    }

    @Override
    public Wishlist deleteWishlistByProductId(HttpServletRequest request, String productId) {
        User user  = jwtUtil.getUserFromRequest(request);
        Wishlist wishlist  =  wishlistRepository.findByProductIdAndUserId(Long.valueOf(productId), user.getId());
        if(wishlist == null) {
            throw  new AppException(ErrorCode.WISHLIST_NOT_FOUND);
        }
        wishlistRepository.deleteById(wishlist.getId());
        return wishlist;
    }
}
