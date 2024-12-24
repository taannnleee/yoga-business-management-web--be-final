package org.example.yogabusinessmanagementweb.controller.user.order;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Order;
import org.example.yogabusinessmanagementweb.common.entities.OrderItem;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderStatusUpdateRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.ListDto;
import org.example.yogabusinessmanagementweb.dto.response.cart.CartResponse;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderCommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderCreationResponse;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderResponse;
import org.example.yogabusinessmanagementweb.dto.response.orderItem.OrderItemResponse;
import org.example.yogabusinessmanagementweb.dto.response.product.ProductResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.CartService;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.example.yogabusinessmanagementweb.service.Impl.WebSocketService;
import org.example.yogabusinessmanagementweb.service.OrderService;
import org.example.yogabusinessmanagementweb.service.ProductService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/order")
@Slf4j
public class OrderController {
    UserService userService;
    UserRepository userRepository;
    EmailService emailService;
    AuthencationService authencationService;
    ProductService productService;
    CartService cartService;
    OrderService orderService;
    WebSocketService webSocketService;
    JwtUtil jwtUtil;
    SimpMessagingTemplate messagingTemplate;

    @PostMapping("/create-order")
    public ApiResponse<?> createOrder(HttpServletRequest request,@RequestBody OrderCreationRequest orderRequest) {
//        System.out.println("Shipping Info: " + orderRequest.getShippingInfo());
//        System.out.println("Payment Method: " + orderRequest.getPaymentMethod());
//        System.out.println("Products: " + orderRequest.getProducts());
//        System.out.println("Total Price: " + orderRequest.getTotalPrice());
        OrderResponse order =  orderService.createOrder(request,orderRequest);

//        Order order  = new Order();
//        webSocketService.sendOrderToAdmins(order);
//        OrderCreationResponse orderCreationResponse = new OrderCreationResponse();
//        String order = "Đã có đơn hàng mới";
        messagingTemplate.convertAndSend("/topic/admin", order);
        return new ApiResponse<>(HttpStatus.OK.value(), "create order success",order);
    }


    //get order theo trang thái truyền xuông
    @GetMapping("/get-all-order-by-status/{status}")
    public ApiResponse<?> getAllOrderByStatus(HttpServletRequest request, @PathVariable String status, @RequestParam(defaultValue = "1") int page,
                                              @RequestParam(defaultValue = "50") int pageSize,
                                              @RequestParam(defaultValue = "createdAt") String sortBy, // Field to sort by
                                              @RequestParam(defaultValue = "desc") String sortDir, // Sort direction: "asc" or "desc"
                                              @RequestParam(required = false) String keyword) {
        Pageable pageable = PageRequest.of(page - 1, pageSize,
                sortDir.equalsIgnoreCase("asc")
                        ? Sort.by(sortBy).ascending()
                        : Sort.by(sortBy).descending());
        ListDto<List<Order>>  orders= orderService.getAllOrderByStatus(request, status,pageable);
        return new ApiResponse<>(HttpStatus.OK.value(), "get all order by status success",orders);

    }
    @PutMapping("/update-comment/{orderItemId}")
    public ApiResponse<?> updateCommentInOrderItem(@PathVariable Long orderItemId, @RequestParam Long commentId) {
        OrderCommentResponse orderItem = orderService.updateCommentInOrderItem(orderItemId, commentId);
        return new ApiResponse<>(HttpStatus.OK.value(), "Comment updated successfully",orderItem);
    }
    @GetMapping("/total-pending")
    public ApiResponse<?> getTotalPending(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        BigDecimal amount = orderService.getTotalPendingAmount(user);
        return new ApiResponse<>(HttpStatus.OK.value(), "Get information amount successfully",amount);
    }
    @GetMapping("/total-shipping")
    public ApiResponse<?> getTotalShipping(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        BigDecimal amount = orderService.getTotalShippingAmount(user);
        return new ApiResponse<>(HttpStatus.OK.value(), "Get information amount successfully",amount);
    }
    @GetMapping("/total-delivered")
    public ApiResponse<?> getTotalDelivered(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        BigDecimal amount = orderService.getTotalDeliveredAmount(user);
        return new ApiResponse<>(HttpStatus.OK.value(), "Get information amount successfully",amount);
    }
    @GetMapping("/total-amount")
    public ApiResponse<?> getTotalAmount(HttpServletRequest request) {
        User user = jwtUtil.getUserFromRequest(request);
        BigDecimal amount = orderService.getTotalAmountByUser(user);
        return new ApiResponse<>(HttpStatus.OK.value(), "Get information amount successfully",amount);
    }
}
