//package org.example.yogabusinessmanagementweb.common.config.ws;
//
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.web.socket.TextMessage;
//import org.springframework.web.socket.WebSocketMessage;
//import org.springframework.web.socket.WebSocketSession;
//import org.springframework.web.socket.handler.TextWebSocketHandler;
//
//import java.io.IOException;
//import java.util.HashSet;
//import java.util.Set;
//
//
//@Slf4j
//public class DataHandler extends TextWebSocketHandler {
//    private final Set<WebSocketSession> adminSessions = new HashSet<>();
//    // Phương thức gọi khi Admin kết nối
//    @Override
//    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
//        adminSessions.add(session);
//        log.info("Admin connected: {}", session.getId());
//    }
//
//    @Override
//    public void handleMessage(WebSocketSession session, WebSocketMessage<?> message) throws IOException {
//        log.info("Message: {}" , message.getPayload());
//        session.sendMessage(new TextMessage("Heeeeeeeeeeeee"));
//    }
//
//    // Phương thức gửi thông báo cho tất cả Admins
//    public void sendToAdmins(String message) {
//        for (WebSocketSession session : adminSessions) {
//            try {
//                if (session.isOpen()) {
//                    session.sendMessage(new TextMessage(message));
//                }
//            } catch (IOException e) {
//                log.error("Error sending message to admin: {}", e.getMessage());
//            }
//        }
//    }
//
//    // Phương thức gọi khi Admin ngắt kết nối
//    @Override
//    public void afterConnectionClosed(WebSocketSession session, org.springframework.web.socket.CloseStatus status) throws Exception {
//        adminSessions.remove(session);
//        log.info("Admin disconnected: {}", session.getId());
//    }
//}
