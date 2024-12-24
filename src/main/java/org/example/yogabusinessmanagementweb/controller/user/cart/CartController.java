package org.example.yogabusinessmanagementweb.controller.user.cart;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.CartItem;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartDeleteRequest;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartItemCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.cart.CartItemResponse;
import org.example.yogabusinessmanagementweb.dto.response.cart.CartResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.CartService;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.example.yogabusinessmanagementweb.service.ProductService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/cart")
@Slf4j
public class CartController {
    UserService userService;
    UserRepository userRepository;
    EmailService emailService;
    AuthencationService authencationService;
    ProductService productService;
    CartService cartService;

    @PostMapping("/increase-to-cart")
    public ApiResponse<?> increaseToCart(HttpServletRequest request,@Valid @RequestBody CartItemCreationRequest cartItemCreationRequest) {
        CartItemResponse cartItem =  cartService.increaseToCart(cartItemCreationRequest,request);
        return new ApiResponse<>(HttpStatus.OK.value(), "increase to cart item success",cartItem);
    }

    @PostMapping("/subtract-from-cart-item")
    public ApiResponse<?> subtractFromCartItem(HttpServletRequest request,@Valid @RequestBody CartItemCreationRequest cartItemCreationRequest) {
        CartItemResponse cartItem =  cartService.subtractFromCartItem(cartItemCreationRequest, request);
        return new ApiResponse<>(HttpStatus.OK.value(), "subtract from cart success",cartItem);
    }

    @PostMapping("/remove-from-cart")
    public ApiResponse<?> removeFromCart(HttpServletRequest request,@Valid @RequestBody CartDeleteRequest cartDeleteRequest) {
        CartResponse cartResponse =  cartService.removeFromCart(request,cartDeleteRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "remove from cart item success",cartResponse);
    }

    @GetMapping("/show-cart")
    public ApiResponse<?> showCart(HttpServletRequest request) {
        CartResponse cartResponse = cartService.showCart(request);
        return new ApiResponse<>(HttpStatus.OK.value(), "show cart success",cartResponse);
    }

    @PostMapping("/add-to-cart")
    public ApiResponse<?> addToCart(HttpServletRequest request,@Valid @RequestBody CartCreationRequest cartCreationRequest) {
        CartResponse cartResponse =  cartService.addToCart(cartCreationRequest,request);
        return new ApiResponse<>(HttpStatus.OK.value(), "add to cart success",cartResponse);
    }
}
