package org.example.yogabusinessmanagementweb.service;

import jakarta.servlet.http.HttpServletRequest;
import org.example.yogabusinessmanagementweb.common.entities.Order;
import org.example.yogabusinessmanagementweb.common.entities.OrderItem;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ListDto;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderCommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderCreationResponse;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderResponse;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.util.List;

public interface OrderService {
    OrderResponse createOrder(HttpServletRequest request, OrderCreationRequest orderRequest);

    OrderCommentResponse updateCommentInOrderItem(Long orderItemId, Long commentId);
    List<OrderResponse> showOrderOfUser(HttpServletRequest request);

    Order updateOrderStatus(Long orderId, String status);
    BigDecimal getTotalPendingAmount(User user);
    BigDecimal getTotalShippingAmount(User user);
    BigDecimal getTotalDeliveredAmount(User user);
    BigDecimal getTotalAmountByUser(User user);

    ListDto<List<Order>> getAllOrderByStatus(HttpServletRequest request, String status, Pageable pageable);

    List<OrderResponse> showOrderOfUserByStatus(HttpServletRequest request, String status, Pageable pageable);

    List<OrderResponse> getDailyRevenue(HttpServletRequest request, String updatedAt,Pageable pageable);

    List<List<OrderResponse>> getMonthRevenue(HttpServletRequest request, String year, Pageable pageable);

    List<String> getListYear(HttpServletRequest request);
}
