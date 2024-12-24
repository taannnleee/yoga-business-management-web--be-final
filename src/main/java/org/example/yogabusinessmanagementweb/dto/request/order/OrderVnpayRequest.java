package org.example.yogabusinessmanagementweb.dto.request.order;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class OrderVnpayRequest {
    private int addressId;
    private String paymentMethod;
    private List<Product> products;

    public static class Product {
        private int id;
        private int quantity;
        private Map<String, Map<String, String>> variants; // Directly use the JSON structure

        // Getters and Setters
        public int getId() {
            return id;
        }

        public void setId(int id) {
            this.id = id;
        }

        public int getQuantity() {
            return quantity;
        }

        public void setQuantity(int quantity) {
            this.quantity = quantity;
        }

        public Map<String, Map<String, String>> getVariants() {
            return variants;
        }

        public void setVariants(Map<String, Map<String, String>> variants) {
            this.variants = variants;
        }
    }
}
