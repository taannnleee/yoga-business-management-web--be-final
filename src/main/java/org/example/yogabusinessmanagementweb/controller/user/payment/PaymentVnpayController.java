package org.example.yogabusinessmanagementweb.controller.user.payment;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderVnpayRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.payment.PaymentVnpayResponse;
import org.example.yogabusinessmanagementweb.service.PaymentService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/payment")
@Slf4j
public class PaymentVnpayController {
    PaymentService paymentService;

    @PostMapping("/vn-pay")
    public ApiResponse<PaymentVnpayResponse> pay(HttpServletRequest request,
                                                 @RequestBody OrderCreationRequest orderRequest) throws JsonProcessingException {
        // You can pass the addressId, paymentMethod, and products from the request body
        PaymentVnpayResponse response = paymentService.createVnPayPayment(request, orderRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "Success", response);
    }



    @GetMapping("/vn-pay-callback")
    public void payCallbackHandler(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Extract VNPay callback parameters
        String status = request.getParameter("vnp_ResponseCode");
        String transactionId = request.getParameter("vnp_TransactionNo");
        String orderInfo = request.getParameter("vnp_OrderInfo");
        String[] infoParts = orderInfo.split("\\|");
        String orderId = infoParts[0];
        String addressId = infoParts[1];
        String paymentMethod = infoParts[2];
        Long vnp_Amount_temp = Long.valueOf(request.getParameter("vnp_Amount"));
        String vnp_Amount = String.valueOf(vnp_Amount_temp/100);
        // Build the frontend URL
        String frontendUrl = "http://localhost:3000/payment/result";

        // Redirect logic based on payment status
        if ("00".equals(status)) {
            // Payment successful
            response.sendRedirect(frontendUrl + "?status=success&transactionId=" + transactionId
                    + "&addressId=" + (addressId != null ? addressId : "unknown")
                    + "&paymentMethod=" + (paymentMethod != null ? paymentMethod : "unknown")
                    + "&vnp_Amount=" + vnp_Amount
            );
        } else {
            response.sendRedirect(frontendUrl + "?status=fail&transactionId=" + "unknown"
                    + "&addressId=" + ("unknown")
                    + "&paymentMethod=" + (paymentMethod != null ? paymentMethod : "unknown")
                    + "&vnp_Amount=" + vnp_Amount
            );
        }
    }


}
