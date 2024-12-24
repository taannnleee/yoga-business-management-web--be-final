package org.example.yogabusinessmanagementweb.service.Impl;
import org.example.yogabusinessmanagementweb.common.entities.Token;
import org.example.yogabusinessmanagementweb.repositories.TokenRepository;
import org.example.yogabusinessmanagementweb.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.service.JwtService;
import org.example.yogabusinessmanagementweb.common.Enum.ETokenType;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.example.yogabusinessmanagementweb.common.Enum.ETokenType.*;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class JwtServiceImpl implements JwtService {
    TokenService tokenService;
    @Autowired
    TokenRepository tokenRepository;

    @Value("${jwt.expiryTime}")
    String expirytime  ;

    @Value("${jwt.secretKey}")
    String secretKey;

    @Value("${jwt.refreshkey}")
    String refreshkey;

    @Value("${jwt.resetKey}")
    String resetKey;

    @Override
    public String generateToken(User user){
        return generateToken(new HashMap<>(), user);
    }

    @Override
    public String generateRefreshToken(User user) {
        return generateRefreshToken(new HashMap<>(), user);
    }

    @Override
    public String generateResetToken(User user) {
        return generateResetToken(new HashMap<>(), user);
    }

    @Override
    public String extractUsername(String token,ETokenType tokenType) {
//        if (!isValid(token, tokenType, userDetails)) {
//            throw new ExpiredTokenException("Token has expired or is invalid.");
//        }
        return extractClaim(token,tokenType, Claims::getSubject);
    }


    @Override
    public Boolean isValid(String token, ETokenType tokenType, UserDetails userDetails) {
        final String username = extractUsername(token, tokenType);

        // Tìm token từ DB
        Token tokenEntity = tokenRepository.findByAccessToken(token).orElse(null);

        // Nếu token không tồn tại hoặc đã bị thu hồi/ hết hạn, trả về false
        if (tokenEntity == null) {
            return false;
        }

        // Kiểm tra xem token có bị thu hồi hoặc hết hạn không
        if (tokenEntity.isRevoked() || tokenEntity.isExpired()) {
            return false;  // Token đã bị thu hồi hoặc hết hạn
        }

        // Kiểm tra username và hết hạn của token
        return username.equals(userDetails.getUsername()) && !isTokenExpried(token, tokenType);
    }

    @Override
    public Boolean isValidRefresh(String token, ETokenType tokenType, UserDetails userDetails) {
        final String username = extractUsername(token, tokenType);

        // Tìm token từ DB
        Token tokenEntity = tokenRepository.findByRefreshToken(token).orElse(null);

        // Nếu token không tồn tại hoặc đã bị thu hồi/ hết hạn, trả về false
        if (tokenEntity == null) {
            return false;
        }

        // Kiểm tra xem token có bị thu hồi hoặc hết hạn không
        if (tokenEntity.isRevoked() || tokenEntity.isExpired()) {
            return false;  // Token đã bị thu hồi hoặc hết hạn
        }

        // Kiểm tra username và hết hạn của token
        return username.equals(userDetails.getUsername()) && !isTokenExpried(token, tokenType);
    }

    private boolean isTokenExpried(String token, ETokenType tokenType) {
        return  extractExpration(token,tokenType).before(new Date());
    }

    private Date extractExpration(String token, ETokenType tokenType) {
        return  extractClaim(token, tokenType,Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> claims, UserDetails userDetails){
        List<String> scopes = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        claims.put("scope", scopes); // Đặt scopes vào claims

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 60*24*24))
                .signWith(getKey(ACCESSTOKEN), SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateRefreshToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60*24*14))
                .signWith(getKey(REFRESHTOKEN), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateResetToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))  //60phuts
                .signWith(getKey(RESETTOKEN), SignatureAlgorithm.HS256)
                .compact();
    }

        private Key getKey(ETokenType tokenType){
        switch(tokenType){
            case ACCESSTOKEN -> {return Keys.hmacShaKeyFor( Decoders.BASE64.decode(secretKey));}
            case REFRESHTOKEN -> {return Keys.hmacShaKeyFor( Decoders.BASE64.decode(refreshkey));}
            case RESETTOKEN -> {return Keys.hmacShaKeyFor( Decoders.BASE64.decode(resetKey));}
            default -> throw new InvalidDataAccessApiUsageException("Token type invalid");
        }
    }
    private <T> T extractClaim(String token,ETokenType tokenType, Function<Claims,T> claimsResolver){
        final Claims claims = extraAllClaim(token,tokenType);
        return claimsResolver.apply(claims);
    }

    private Claims extraAllClaim(String token, ETokenType tokenType) {
        return Jwts.parser().setSigningKey(getKey(tokenType)).build().parseClaimsJws(token).getBody();
    }

    @Override
    public void revokeToken(String token, ETokenType tokenType) {
        // Kiểm tra xem token có hết hạn không
        if (isTokenExpried(token, tokenType)) {
            throw new InvalidDataAccessApiUsageException("Token is already expired");
        }

        // Lấy thông tin claims của token
        Claims claims = extraAllClaim(token, tokenType);

        // Tạo token mới với thời gian hết hạn là hiện tại để thu hồi token cũ
        Date currentDate = new Date(System.currentTimeMillis());

        // Tìm token trong cơ sở dữ liệu và cập nhật trạng thái
        Token tokenEntity = tokenRepository.findByAccessToken(token).orElse(null);

        if (tokenEntity != null) {
            tokenEntity.setExpired(true);  // Đánh dấu là đã hết hạn
            tokenEntity.setRevoked(true);  // Đánh dấu là đã thu hồi quyền
            tokenRepository.save(tokenEntity);  // Lưu lại vào DB
        }
    }
}
