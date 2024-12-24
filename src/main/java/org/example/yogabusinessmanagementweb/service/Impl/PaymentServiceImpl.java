package org.example.yogabusinessmanagementweb.service.Impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.example.yogabusinessmanagementweb.common.config.payment.VNPAYConfig;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.order.OrderVnpayRequest;
import org.example.yogabusinessmanagementweb.dto.response.payment.PaymentVnpayResponse;
import org.example.yogabusinessmanagementweb.service.PaymentService;
import org.example.yogabusinessmanagementweb.utils.VNPayUtil;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;
@Service
@RequiredArgsConstructor
public class PaymentServiceImpl implements PaymentService {
    private final VNPAYConfig vnPayConfig;

    @Override
    public PaymentVnpayResponse createVnPayPayment(HttpServletRequest request,
                                                   OrderCreationRequest orderRequest) throws JsonProcessingException {
        long amount = Integer.parseInt(request.getParameter("amount")) * 100L;
        String bankCode = request.getParameter("bankCode");
        Map<String, String> vnpParamsMap = vnPayConfig.getVNPayConfig(orderRequest);
        vnpParamsMap.put("vnp_Amount", String.valueOf(amount));
        if (bankCode != null && !bankCode.isEmpty()) {
            vnpParamsMap.put("vnp_BankCode", bankCode);
        }
        vnpParamsMap.put("vnp_IpAddr", VNPayUtil.getIpAddress(request));
        //build query url
        String queryUrl = VNPayUtil.getPaymentURL(vnpParamsMap, true);
        String hashData = VNPayUtil.getPaymentURL(vnpParamsMap, false);
        String vnpSecureHash = VNPayUtil.hmacSHA512(vnPayConfig.getSecretKey(), hashData);
        queryUrl += "&vnp_SecureHash=" + vnpSecureHash;
        String paymentUrl = vnPayConfig.getVnp_PayUrl() + "?" + queryUrl;
        return PaymentVnpayResponse.builder()
                .code(00)
                .message("success")
                .paymentUrl(paymentUrl)
                .addressId(orderRequest.getAddressId())
                .paymentMethod(orderRequest.getPaymentMethod())
                .build();
    }


}
