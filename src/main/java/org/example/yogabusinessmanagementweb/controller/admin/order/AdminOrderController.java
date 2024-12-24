package org.example.yogabusinessmanagementweb.controller.admin.order;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Order;
import org.example.yogabusinessmanagementweb.dto.request.lecture.LectureCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderStatusUpdateRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.lecture.LectureResponse;
import org.example.yogabusinessmanagementweb.dto.response.order.OrderResponse;
import org.example.yogabusinessmanagementweb.service.LecturesService;
import org.example.yogabusinessmanagementweb.service.OrderService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminOrderController {
    OrderService orderService;

    @GetMapping("/get-all-order-of-user")
    public ApiResponse<?> getAllOrder(HttpServletRequest request) {
        List<OrderResponse> orderResponse = orderService.showOrderOfUser(request);
        return new ApiResponse<>(HttpStatus.OK.value(), "show order success",orderResponse);
    }

    @GetMapping("/get-all-order-of-user-by-status/{status}")
    public ApiResponse<?> getAllOrder(HttpServletRequest request, @PathVariable String status, @RequestParam(defaultValue = "1") int page,
                                      @RequestParam(defaultValue = "50") int pageSize,
                                      @RequestParam(defaultValue = "createdAt") String sortBy, // Field to sort by
                                      @RequestParam(defaultValue = "desc") String sortDir, // Sort direction: "asc" or "desc"
                                      @RequestParam(required = false) String keyword) {
        Pageable pageable = PageRequest.of(page - 1, pageSize,
                sortDir.equalsIgnoreCase("asc")
                        ? Sort.by(sortBy).ascending()
                        : Sort.by(sortBy).descending());
        List<OrderResponse> orderResponse = orderService.showOrderOfUserByStatus(request, status,pageable);
        return new ApiResponse<>(HttpStatus.OK.value(), "show order success",orderResponse);
    }
    @PatchMapping("/update-order-status/{orderId}")
    public ApiResponse<?> updateOrderStatus(
            @PathVariable Long orderId,
            @RequestBody OrderStatusUpdateRequest request) {

        // Cập nhật trạng thái đơn hàng
        Order updatedOrder = orderService.updateOrderStatus(orderId, request.getStatus());

        // Trả về đơn hàng đã cập nhật
        return new ApiResponse<>(HttpStatus.OK.value(), "change status order success",updatedOrder);
    }

    // doanh thu theo ngày, chỉ lấy những đơn đã hoàn thành
    @GetMapping("/get-daily-revenue")
    public ApiResponse<?> getAllOrderByDaily(HttpServletRequest request, @RequestParam(defaultValue = "1") int page,
                                      @RequestParam(defaultValue = "50") int pageSize,
                                      @RequestParam(defaultValue = "2024-11-27") String updatedAt,
                                      @RequestParam(defaultValue = "updatedAt") String sortBy, // Field to sort by
                                      @RequestParam(defaultValue = "desc") String sortDir, // Sort direction: "asc" or "desc"
                                      @RequestParam(required = false) String keyword) {
        Pageable pageable = PageRequest.of(page - 1, pageSize,
                sortDir.equalsIgnoreCase("asc")
                        ? Sort.by(sortBy).ascending()
                        : Sort.by(sortBy).descending());
        List<OrderResponse> orderResponse = orderService.getDailyRevenue(request,updatedAt,pageable);
        return new ApiResponse<>(HttpStatus.OK.value(), "show order success",orderResponse);
    }

    // doanh thu theo tháng của năm, chỉ lấy những đơn đã hoàn thành
    @GetMapping("/get-month-revenue")
    public ApiResponse<?> getAllOrderByMonth(HttpServletRequest request, @RequestParam(defaultValue = "1") int page,
                                             @RequestParam(defaultValue = "50") int pageSize,
                                             @RequestParam(defaultValue = "2024") String year,
                                             @RequestParam(defaultValue = "updatedAt") String sortBy, // Field to sort by
                                             @RequestParam(defaultValue = "desc") String sortDir, // Sort direction: "asc" or "desc"
                                             @RequestParam(required = false) String keyword) {
        Pageable pageable = PageRequest.of(page - 1, pageSize,
                sortDir.equalsIgnoreCase("asc")
                        ? Sort.by(sortBy).ascending()
                        : Sort.by(sortBy).descending());
        List<List<OrderResponse>> orderResponse = orderService.getMonthRevenue(request,year,pageable);
        return new ApiResponse<>(HttpStatus.OK.value(), "show order success",orderResponse);
    }

    //lấy danh sách các năm tồn tại trong của hàng. để hiern thị leen combobox số chọn số năm
    @GetMapping("/get-list-year")
    public ApiResponse<?> getListYear(HttpServletRequest request) {

        List<String> list = orderService.getListYear(request);
        return new ApiResponse<>(HttpStatus.OK.value(), "get list year success",list);
    }
}
