package org.example.yogabusinessmanagementweb.common.config.ws;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.*;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Đảm bảo sử dụng ws:// cho WebSocket hoặc wss:// nếu sử dụng SSL
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns("*")  // Cẩn thận với CORS trong môi trường sản xuất
                .withSockJS(); // SockJS fallback cho các trình duyệt không hỗ trợ WebSocket
    }

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.setApplicationDestinationPrefixes("/app"); // Prefix cho các endpoint gửi tới server
        registry.enableSimpleBroker("/topic"); // Prefix cho các message gửi đến client
    }
}
