package org.example.yogabusinessmanagementweb.controller.user.product;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.ListDto;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.example.yogabusinessmanagementweb.service.ProductService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.common.entities.Product;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/product")
@Slf4j
public class ProductController {
    UserService userService;
    UserRepository userRepository;
    EmailService emailService;
    AuthencationService authencationService;
    ProductService productService;
    SimpMessagingTemplate messagingTemplate;

    @GetMapping("/all")
    public ApiResponse<?> getAllProduct(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String keyword) { // Nhận từ khóa tìm kiếm từ request
        try {
            Pageable pageable = PageRequest.of(page - 1, size);

            // Nếu có từ khóa tìm kiếm thì gọi phương thức searchProducts
            Page<ProductResponse> productPage = productService.searchProducts(keyword, pageable);

            return new ApiResponse<>(HttpStatus.OK.value(), "Get all products successfully", productPage);
        } catch (RuntimeException e) {
            return new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        }
    }
    @GetMapping("/top-selling")
    public ApiResponse<?> getTop10BestSellingProducts() { // Nhận từ khóa tìm kiếm từ request

            // Nếu có từ khóa tìm kiếm thì gọi phương thức searchProducts
        List<Product> products = productService.getTop10BestSellingProducts();

        return new ApiResponse<>(HttpStatus.OK.value(), "Get all products successfully", products);

    }
    @GetMapping("/{id}")
    public ApiResponse<?> getById(@PathVariable String id){
        ProductResponse productResponse = productService.getById(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get product detail successfully",productResponse);
    }
    @GetMapping("/filter")
    public ApiResponse<?> filterProducts(
        @RequestParam(required = false) Long subCategoryId,
        @RequestParam(required = false) Long categoryId,
        @RequestParam(defaultValue = "1") int page,
        @RequestParam(defaultValue = "10") int pageSize,
        @RequestParam(defaultValue = "title") String sortBy, // Field to sort by
        @RequestParam(defaultValue = "asc") String sortDir, // Sort direction: "asc" or "desc"
        @RequestParam(required = false) String keyword) {
        Pageable pageable = PageRequest.of(page - 1, pageSize,
                sortDir.equalsIgnoreCase("asc")
                        ? Sort.by(sortBy).ascending()
                        : Sort.by(sortBy).descending());
        ListDto<List<ProductResponse>> response = productService.filterProducts(subCategoryId, categoryId, keyword, pageable);
        return new ApiResponse<>(HttpStatus.OK.value(), "Filtered products retrieved successfully", response);
    }

}
