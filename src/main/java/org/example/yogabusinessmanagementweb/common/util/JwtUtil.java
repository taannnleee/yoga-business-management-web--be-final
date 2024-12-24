package org.example.yogabusinessmanagementweb.common.util;

import jakarta.servlet.http.HttpServletRequest;
import org.example.yogabusinessmanagementweb.common.Enum.ETokenType;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.service.JwtService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {
    @Autowired
    private JwtService jwtService;

    @Autowired
    @Lazy
    private UserService userService;

    public User getUserFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Authorization header is missing or invalid");
        }

        String token = authorizationHeader.substring(7); // Cắt bỏ tiền tố "Bearer "

        // Giải mã token để lấy userName
        String userName = jwtService.extractUsername(token, ETokenType.ACCESSTOKEN);

        // Tìm user từ userName
        return userService.findUserByUserName(userName);
    }
}
