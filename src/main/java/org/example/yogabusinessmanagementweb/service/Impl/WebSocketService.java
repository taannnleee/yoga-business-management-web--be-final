package org.example.yogabusinessmanagementweb.service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
//import org.example.yogabusinessmanagementweb.common.config.ws.DataHandler;
import org.example.yogabusinessmanagementweb.common.entities.Order;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;

@Service
@RequiredArgsConstructor
@Slf4j
public class WebSocketService {

//    private final DataHandler dataHandler;  // Lấy đối tượng WebSocketHandler để gửi tin nhắn
//
//    // Phương thức gửi thông báo đơn hàng cho Admin
//    public void sendOrderToAdmins(Order order) {
//        String orderDetails = "Đây là order mới ";  // Cần định dạng lại dữ liệu cho phù hợp với Admin
//
//        // Gửi thông báo cho tất cả Admins
//        dataHandler.sendToAdmins(orderDetails);
//    }
//
//    // Phương thức để đăng ký WebSocket session của admin
//    public void registerAdminSession(WebSocketSession session) {
//        try {
//            dataHandler.afterConnectionEstablished(session); // Đăng ký session WebSocket của admin
//            log.info("Admin session registered: {}", session.getId());
//        } catch (Exception e) {
//            log.error("Failed to register admin WebSocket session", e);
//        }
//    }
//
//    // Hủy đăng ký session WebSocket của admin
//    public void unregisterAdminSession(WebSocketSession session) {
//        try {
//            dataHandler.afterConnectionClosed(session, org.springframework.web.socket.CloseStatus.NORMAL);
//            log.info("Admin session unregistered: {}", session.getId());
//        } catch (Exception e) {
//            log.error("Failed to unregister admin WebSocket session", e);
//        }
//    }
}
