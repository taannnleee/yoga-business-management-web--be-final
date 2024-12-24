package org.example.yogabusinessmanagementweb.controller.user.wishlist;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.common.entities.Wishlist;
import org.example.yogabusinessmanagementweb.dto.request.wishlist.WishListRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.example.yogabusinessmanagementweb.service.TeacherService;
import org.example.yogabusinessmanagementweb.service.WishlistService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/wishlist")
@Slf4j
public class WishListController {
    WishlistService wishlistService;

    @PostMapping("/add-wishlist")
    public ApiResponse<?> addWishlist(HttpServletRequest request, @RequestBody WishListRequest wishListRequest ) {
        wishlistService.addWishlist(request,wishListRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "add wish list success" );
    }
    //get wish list
    @GetMapping("/get-wishlist-of-user")
    public ApiResponse<?> getWishlistOfUser(HttpServletRequest request) {
        List<Wishlist> list  = wishlistService.getWishlistOfUser(request);
        return new ApiResponse<>(HttpStatus.OK.value(), "get all wish list success",list );
    }

    //xóa wish list theo wishlistId
    @DeleteMapping("/delete-wishlist-of-user/{wishlistId}")
    public ApiResponse<?> deleteWishlist(HttpServletRequest request, @PathVariable String wishlistId ) {
        Wishlist  wishlist  = wishlistService.deleteWishlistOfUser(request,wishlistId);
        return new ApiResponse<>(HttpStatus.OK.value(), "delete wish list success",wishlist );
    }

    //xóa wish list theo product id
    @DeleteMapping("/delete-wishlist-by-product-id/{productId}")
    public ApiResponse<?> deleteWishlistByProductId(HttpServletRequest request, @PathVariable String productId ) {
        Wishlist  wishlist  = wishlistService.deleteWishlistByProductId(request,productId);
        return new ApiResponse<>(HttpStatus.OK.value(), "delete wish list success",wishlist );
    }

    // hieen thị trái tim mày đỏ khi get product detail lên
    @PostMapping("/get-wishlist-exists")
    public ApiResponse<?> getWishlistExists(HttpServletRequest request,@RequestBody WishListRequest wishListRequest) {
        Wishlist wishList  = wishlistService.getWishlistExists(request,wishListRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "get wish list exists success",wishList );
    }
}
