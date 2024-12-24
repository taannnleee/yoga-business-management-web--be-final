package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.Enum.ETokenType;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JwtService {
    String generateRefreshToken(User user);
    String generateResetToken(User user);
    String generateToken(User user);
    String extractUsername(String token, ETokenType tokenType);
    Boolean isValid(String token,ETokenType tokenType, UserDetails userDetails);
    Boolean isValidRefresh(String token, ETokenType tokenType, UserDetails userDetails);
    void revokeToken(String token, ETokenType tokenType);
}
