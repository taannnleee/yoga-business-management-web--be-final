package org.example.yogabusinessmanagementweb.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderVnpayRequest;
import org.example.yogabusinessmanagementweb.dto.response.payment.PaymentVnpayResponse;
import org.springframework.web.bind.annotation.RequestParam;

public interface PaymentService {
    PaymentVnpayResponse createVnPayPayment(HttpServletRequest request,
                                            OrderCreationRequest orderRequest) throws JsonProcessingException;

}
