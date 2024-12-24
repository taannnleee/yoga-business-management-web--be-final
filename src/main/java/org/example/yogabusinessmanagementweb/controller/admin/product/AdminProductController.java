package org.example.yogabusinessmanagementweb.controller.admin.product;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.dto.request.product.ProductCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.example.yogabusinessmanagementweb.service.ProductService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminProductController {
    UserService userService;
    UserRepository userRepository;
    EmailService emailService;
    AuthencationService authencationService;
    ProductService productService;
    SimpMessagingTemplate messagingTemplate;

    @PostMapping("/add-product")
    public ApiResponse<?> creatProduct(@Valid  @RequestBody ProductCreationRequest productCreationRequest) {
        Product addProductResponse = productService.addProduct(productCreationRequest);
        messagingTemplate.convertAndSend("/topic/notification", addProductResponse.getId());
        return new ApiResponse<>(HttpStatus.OK.value(), "create product  successfully",addProductResponse);
    }

    @GetMapping("/get-all-product")
    public ApiResponse<?> getAllProduct(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "createdAt") String sortBy, // Field to sort by
            @RequestParam(defaultValue = "desc") String sortDir) { // Nhận từ khóa tìm kiếm từ request
        try {
            Pageable pageable = PageRequest.of(page - 1, size,
                    sortDir.equalsIgnoreCase("asc")
                            ? Sort.by(sortBy).ascending()
                            : Sort.by(sortBy).descending());

//            Pageable pageable = PageRequest.of(page - 1, size,Sort.by(sortBy).ascending());

            // Nếu có từ khóa tìm kiếm thì gọi phương thức searchProducts
            Page<ProductResponse> productPage = productService.searchProducts(keyword, pageable);

            return new ApiResponse<>(HttpStatus.OK.value(), "Get all products successfully", productPage);
        } catch (RuntimeException e) {
            return new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        }
    }

    @GetMapping("/get-all-product-by-subcategory/{id}")
    public ApiResponse<?> getAllProductBySubcategory(
            @PathVariable Long id,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String keyword) { // Nhận từ khóa tìm kiếm từ request
        try {
            Pageable pageable = PageRequest.of(page - 1, size);

            // Nếu có từ khóa tìm kiếm thì gọi phương thức searchProducts
            Page<ProductResponse> productPage = productService.getAllProductBySubcategory(String.valueOf(id),keyword, pageable);

            return new ApiResponse<>(HttpStatus.OK.value(), "Get all products successfully", productPage);
        } catch (RuntimeException e) {
            return new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        }
    }


    // hàm xóa thẳng bản ghi(thường ít ai dùng)
    @PostMapping("/delete-product/{productId}")
    public ApiResponse<?> deleteProduct(@Valid @PathVariable String productId) {
        try{
            productService.delete(productId);
            return new ApiResponse<>(HttpStatus.OK.value(), "delete product  successfully");
        }catch (Exception e){
            return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),e.getMessage());
        }
    }

    // hàm xoá product bằng cách tắt trạng thái status
    @GetMapping("/delete-status-product/{productId}")
    public ApiResponse<?> deleteProductWithStatus(@Valid @PathVariable String productId){;
        try{
            productService.deleteProductWithStatus(productId);
            return new ApiResponse<>(HttpStatus.OK.value(), "delete product  successfully");
        }catch (Exception e){
            return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(),e.getMessage());
        }
    }
}
