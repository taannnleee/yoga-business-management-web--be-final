package org.example.yogabusinessmanagementweb.controller.user.comment;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.comment.CommentCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.ListDto;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentOrderResponse;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.CommentService;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.example.yogabusinessmanagementweb.service.ProductService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/comment")
@Slf4j
public class CommentController {
    CommentService commentService;
    JwtUtil jwtUtil;
    @GetMapping("/all")
    public ApiResponse<?> all(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size) { // Nhận từ khóa tìm kiếm từ request
        try {
            // Tạo Pageable từ trang và kích thước
            Pageable pageable = PageRequest.of(page - 1, size);

            // Gọi service để lấy dữ liệu phân trang
            List<CommentResponse> commentResponseList = commentService.all(pageable);

            // Trả về kết quả
            return new ApiResponse<>(HttpStatus.OK.value(), "Get all comments successfully", commentResponseList);
        } catch (RuntimeException e) {
            // Nếu có lỗi xảy ra
            return new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        }
    }

    @GetMapping("/{id}")
    public ApiResponse<?> getById(@PathVariable String id){
        CommentResponse commentResponse = commentService.getById(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get comment successfully",commentResponse);
    }
    @GetMapping("/by-product/{id}")
    public ApiResponse<?> getByProduct(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(defaultValue = "createdAt") String sortBy, // Field to sort by
            @RequestParam(defaultValue = "desc") String sortDir,
            @RequestParam(defaultValue = "-1") int ratePoint,
            @PathVariable String id)
    {
            // Tạo Pageable từ trang và kích thước
        Pageable pageable = PageRequest.of(page - 1, pageSize,
                sortDir.equalsIgnoreCase("asc")
                        ? Sort.by(sortBy).ascending()
                        : Sort.by(sortBy).descending());

            // Gọi service để lấy dữ liệu phân trang
            ListDto<List<CommentResponse>> commentResponseList = commentService.byProduct(pageable,id,ratePoint);

            // Trả về kết quả
            return new ApiResponse<>(HttpStatus.OK.value(), "Get all comments successfully", commentResponseList);
    }
    @PostMapping()
    public ApiResponse<?> addComment(HttpServletRequest servletRequestm, @RequestBody CommentCreationRequest request) {
            User user  = jwtUtil.getUserFromRequest(servletRequestm);

        // Xử lý thêm comment, mặc định parentComment = null
            CommentOrderResponse commentResponse = commentService.addComment(request,user);
            // Trả về kết quả
            return new ApiResponse<>(HttpStatus.CREATED.value(), "Comment added successfully", commentResponse);
    }
}
