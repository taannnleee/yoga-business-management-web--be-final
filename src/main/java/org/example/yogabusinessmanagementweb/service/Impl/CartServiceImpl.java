package org.example.yogabusinessmanagementweb.service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.mapper.CartItemMapper;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartDeleteRequest;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartItemCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.cart.CartItemResponse;
import org.example.yogabusinessmanagementweb.dto.request.cart.CartCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.cart.CartResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.CartItemRepository;
import org.example.yogabusinessmanagementweb.repositories.CartRepository;
import org.example.yogabusinessmanagementweb.service.*;
import org.example.yogabusinessmanagementweb.common.entities.Cart;
import org.example.yogabusinessmanagementweb.common.entities.CartItem;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.mapper.Mappers;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.*;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class CartServiceImpl implements CartService {
    UserService userService;
    ProductService productService;
    CartRepository cartRepository;
    CartItemRepository cartItemRepository;
    JwtService jwtService;
    JwtUtil jwtUtil;
    CartItemService cartItemService;
    CartItemMapper cartItemMapper;

    @Override
    public CartItemResponse increaseToCart(CartItemCreationRequest cartItemCreationRequest, HttpServletRequest request) {
        CartItem cartItem =  cartItemService.findCartItemById(cartItemCreationRequest.getId());
        cartItem.setQuantity(cartItem.getQuantity() + cartItemCreationRequest.getQuantity());

        BigDecimal price = cartItem.getProduct().getPrice(); // Giá sản phẩm
        int quantity = cartItem.getQuantity();

        BigDecimal totalPrice = price.multiply(BigDecimal.valueOf(quantity));
        cartItem.setTotalPrice(totalPrice);

        cartItemRepository.save(cartItem);

        Optional<Cart> cartOptional =  cartRepository.findCartByCartItems(cartItem);
        if(cartOptional.isEmpty()) {
            throw new AppException(ErrorCode.CART_NOT_FOUND);
        }
        Cart cart = cartOptional.get();


        //khởi tạo totalPrice
        BigDecimal totalPriceCart = BigDecimal.ZERO;
        for (CartItem item : cart.getCartItems()) {

            totalPriceCart = totalPriceCart.add(item.getTotalPrice());
        }

        cart.setTotalPrice(totalPriceCart);
        cart.setTotalItem(cart.getCartItems().size());

        cartRepository.save(cart);


        return cartItemMapper.toCartItemResponse(cartItem);

    }

    @Override
    public CartResponse showCart(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        Optional<Cart> cartOptional = cartRepository.findCartByUser(user);


        // Nếu không tìm thấy giỏ hàng, có thể trả về null hoặc một thông điệp lỗi tùy theo yêu cầu
        if (cartOptional.isEmpty()) {
            throw new AppException(ErrorCode.CART_NOT_FOUND);
        }

        Cart cart = cartOptional.get();

        List<CartItemResponse> itemDTOS = Mappers.mapperEntityToDto(cart.getCartItems(), CartItemResponse.class);

        CartResponse response  = Mappers.convertToDto(cart, CartResponse.class);
        response.setCartItem(itemDTOS);
        return response;
    }


    @Override
    public CartResponse removeFromCart(HttpServletRequest request, CartDeleteRequest cartCreationRequest) {
        User user = jwtUtil.getUserFromRequest(request);

        Optional<Cart> cartOptional = cartRepository.findCartByUser(user);
        // Nếu không tìm thấy giỏ hàng, có thể trả về null hoặc một thông điệp lỗi tùy theo yêu cầu
        if (cartOptional.isEmpty()) {
            throw new AppException(ErrorCode.CART_NOT_FOUND);
        }
        Cart cart = cartOptional.get();

        CartItem itemToRemove = null;
        for (CartItem item : cart.getCartItems()) {
            if (item.getProduct().getId().equals(Long.parseLong(cartCreationRequest.getProductId()))) {
                itemToRemove = item;
                break;
            }
        }

        if (itemToRemove != null) {
            cart.getCartItems().remove(itemToRemove);
            cartItemRepository.delete(itemToRemove);

            // Bước 5: Cập nhật lại totalItem và totalPrice của Cart
            cart.setTotalItem(cart.getCartItems().size());

            BigDecimal totalPrice = BigDecimal.ZERO;
            for (CartItem item : cart.getCartItems()) {
                totalPrice = totalPrice.add(item.getTotalPrice());
            }
            cart.setTotalPrice(totalPrice);
            cartRepository.save(cart);
        } else {
            throw new RuntimeException("CartItem not found");
        }

        // Trả về response
        List<CartItemResponse> itemDTOS = Mappers.mapperEntityToDto(cart.getCartItems(), CartItemResponse.class);

        CartResponse response = Mappers.convertToDto(cart, CartResponse.class);
        response.setCartItem(itemDTOS);
        return response;
    }


    @Override
    public CartItemResponse subtractFromCartItem(CartItemCreationRequest cartItemCreationRequest, HttpServletRequest request) {

        CartItem cartItem =  cartItemService.findCartItemById(cartItemCreationRequest.getId());
        cartItem.setQuantity(cartItem.getQuantity() - cartItemCreationRequest.getQuantity());

        BigDecimal price = cartItem.getProduct().getPrice(); // Giá sản phẩm
        int quantity = cartItem.getQuantity();

        BigDecimal totalPrice = price.multiply(BigDecimal.valueOf(quantity));
        cartItem.setTotalPrice(totalPrice);

        cartItemRepository.save(cartItem);

        Optional<Cart> cartOptional =  cartRepository.findCartByCartItems(cartItem);
        if(cartOptional.isEmpty()) {
            throw new AppException(ErrorCode.CART_NOT_FOUND);
        }
        Cart cart = cartOptional.get();


        //khởi tạo totalPrice
        BigDecimal totalPriceCart = BigDecimal.ZERO;
        for (CartItem item : cart.getCartItems()) {

            totalPriceCart = totalPriceCart.add(item.getTotalPrice());
        }

        cart.setTotalPrice(totalPriceCart);
        cart.setTotalItem(cart.getCartItems().size());

        cartRepository.save(cart);


        return cartItemMapper.toCartItemResponse(cartItem);
    }


    @Override
    public CartResponse addToCart(CartCreationRequest cartCreationRequest, HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        Optional<Cart> cartResponse = cartRepository.findCartByUser(user);
        Cart cart = cartResponse.get();

        // Kiểm tra xem sản phẩm đã có trong giỏ hàng chưa
        CartItem existingItem = null;

        for (CartItem item : cart.getCartItems()) {
            // So sánh productId và variants (các tùy chọn như size, color...)
            if (item.getProduct().getId().equals(Long.parseLong(cartCreationRequest.getProductId())) &&
                    variantsMatch(item.getCurrentVariant(), cartCreationRequest.getCurrentVariant())) {
                existingItem = item;
                break;
            }
        }

        Iterator<Map.Entry<String, Map<String, String>>> iterator = cartCreationRequest.getCurrentVariant().entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Map<String, String>> entry = iterator.next();

            String variantType = entry.getKey();  // "size", "thin", "color"
            Map<String, String> variantDetails = entry.getValue();

            // Lấy value và image
            String value = variantDetails.get("value");
            String image = variantDetails.get("image");

            // In kết quả
            System.out.println("Variant Type: " + variantType);
            System.out.println("Value: " + value);
            System.out.println("Image: " + image);
            System.out.println();
        }

        if (existingItem != null) {
            // Nếu sản phẩm đã tồn tại và các variants giống nhau, tăng số lượng
            existingItem.setQuantity(existingItem.getQuantity() + cartCreationRequest.getQuantity());

            BigDecimal price = existingItem.getProduct().getPrice(); // Giá sản phẩm
            int quantity = existingItem.getQuantity();

            BigDecimal totalPrice = price.multiply(BigDecimal.valueOf(quantity));
            existingItem.setTotalPrice(totalPrice);
        } else {
            // Nếu sản phẩm chưa tồn tại hoặc variants khác nhau, tạo CartItem mới
            CartItem newItem = new CartItem();
            newItem.setProduct(productService.getProductById(cartCreationRequest.getProductId())); // Tìm sản phẩm
            newItem.setQuantity(cartCreationRequest.getQuantity());
            newItem.setTotalPrice(newItem.getProduct().getPrice().multiply(BigDecimal.valueOf(newItem.getQuantity())));
            newItem.setCurrentVariant(cartCreationRequest.getCurrentVariant());

            // Thêm CartItem vào cart
            cart.getCartItems().add(newItem);
        }

        // Cập nhật tổng số mặt hàng và tổng giá
        cart.setTotalItem(cart.getCartItems().size());

        BigDecimal totalPrice = BigDecimal.ZERO;
        for (CartItem item : cart.getCartItems()) {
            totalPrice = totalPrice.add(item.getTotalPrice());
        }
        cart.setTotalPrice(totalPrice);


        // lưu lại cart item

        // Lưu lại cart
        cartRepository.save(cart);

        // Trả về response
        List<CartItemResponse> itemDTOS = Mappers.mapperEntityToDto(cart.getCartItems(), CartItemResponse.class);

        CartResponse response  = Mappers.convertToDto(cart, CartResponse.class);
        response.setCartItem(itemDTOS);
        return response;
    }

    private boolean variantsMatch(Map<String, Map<String, String>> variants1, Map<String, Map<String, String>> variants2) {
        // Kiểm tra nếu các variants (size, color, v.v.) giống nhau
        if (variants1.size() != variants2.size()) {
            return false;
        }

        for (String variantType : variants1.keySet()) {
            Map<String, String> variantDetails1 = variants1.get(variantType);
            Map<String, String> variantDetails2 = variants2.get(variantType);

            // Kiểm tra từng variant
            if (variantDetails1 == null || variantDetails2 == null ||
                    !variantDetails1.get("value").equals(variantDetails2.get("value")) ||
                    !variantDetails1.get("image").equals(variantDetails2.get("image"))) {
                return false;
            }
        }

        return true;
    }


}
