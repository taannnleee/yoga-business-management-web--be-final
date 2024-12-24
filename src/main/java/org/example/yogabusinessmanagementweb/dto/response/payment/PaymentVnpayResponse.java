package org.example.yogabusinessmanagementweb.dto.response.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class PaymentVnpayResponse {
    private int code; // Ensure this is an int, as your logic uses integers
    private String message;
    private String paymentUrl;
    private String addressId;
    private String paymentMethod;

}
