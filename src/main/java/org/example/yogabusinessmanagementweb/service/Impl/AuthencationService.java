package org.example.yogabusinessmanagementweb.service.Impl;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.apache.commons.lang3.StringUtils;
import org.example.yogabusinessmanagementweb.common.Enum.ERole;
import org.example.yogabusinessmanagementweb.common.Enum.ETokenType;
import org.example.yogabusinessmanagementweb.common.entities.Cart;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.dto.request.user.ChangePasswordRequest;
import org.example.yogabusinessmanagementweb.dto.request.user.LoginRequest;
import org.example.yogabusinessmanagementweb.dto.request.user.ResetPasswordRequest;
import org.example.yogabusinessmanagementweb.dto.response.token.TokenRespone;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.CartRepository;
import org.example.yogabusinessmanagementweb.repositories.TokenRepository;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.JwtService;
import org.example.yogabusinessmanagementweb.service.TokenService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.common.Enum.EMessage;
import org.example.yogabusinessmanagementweb.common.entities.Token;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.example.yogabusinessmanagementweb.common.util.OTPGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.annotation.AccessType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;

import static org.example.yogabusinessmanagementweb.common.Enum.ETokenType.*;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class AuthencationService {
    CartRepository cartRepository;
    AuthenticationManager authenticationManager;
    UserRepository userRepository;
    JwtService jwtService;
    TokenService tokenService;
    UserService userService;
    PasswordEncoder passwordEncoder;
    EmailService emailService;
    TokenRepository tokenRepository;
    private final JwtUtil jwtUtil;


    public TokenRespone authentication(LoginRequest loginRequest){
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }
        catch (BadCredentialsException e) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }

        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Username or Password is incorrect"));

        if(user.isStatus()==false){
            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
        }

        String accessToken =  jwtService.generateToken(user);
        String refreshToken =  jwtService.generateRefreshToken(user);

        saveUserToken(user, accessToken,refreshToken);

        Token savedToken = Token.builder()
                        .username(user.getUsername())
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .user(user)
                        .build();

        return TokenRespone.builder()
                .accesstoken(savedToken.getAccessToken())
                .refreshtoken(savedToken.getRefreshToken())
                .userid(user.getId())
                .build();
    }

    public String logout(HttpServletRequest request) {

        // Lấy accessToken
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Authorization header is missing or invalid");
        }
        String token = authorizationHeader.substring(7);

        // Extract user từ token
        final String userName = jwtService.extractUsername(token, ACCESSTOKEN);

        // Revoke quyền của accessToken
        jwtService.revokeToken(token, ACCESSTOKEN);

        // Kiểm tra và xoóa token trong DB
//        Token tokenCurrent = tokenService.getTokenByUsername(userName);
//        if (tokenCurrent != null) {
//            tokenService.delete(tokenCurrent);
//        }
        return "Token revoked and deleted!";
    }

    public TokenRespone authenticationAdmin(LoginRequest loginRequest){
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }
        catch (BadCredentialsException e) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }

        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Username or Password is incorrect"));

    //        if(user.isStatus()==false){
    //            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
    //        }


        String accessToken =  jwtService.generateToken(user);
        String refreshToken =  jwtService.generateRefreshToken(user);

        //save token vào db và đông thời chỉnh lai trạng thái của các token phía trước
//        revokeAllUserTokens(user);
        saveUserToken(user, accessToken,refreshToken);

        Token savedToken = Token.builder()
                .username(user.getUsername())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(user)
                .build();


        return TokenRespone.builder()
                .accesstoken(savedToken.getAccessToken())
                .refreshtoken(savedToken.getRefreshToken())
                .userid(user.getId())
                .build();
    }

    public TokenRespone refresh(HttpServletRequest loginRequest) {
        //validate xem token cos rỗng không
        String refresh_token = loginRequest.getHeader("x-token");
        if(StringUtils.isBlank(refresh_token)){
            throw new AppException(ErrorCode.TOKEN_EMPTY);
        }
        //extract user from token
        final String userName = jwtService.extractUsername(refresh_token, REFRESHTOKEN);

        //check it into db
        User user =  userService.findByUserName(userName);


        //validate xem token có hợp lệ không
        if(!jwtService.isValidRefresh(refresh_token, REFRESHTOKEN,user)){
            throw new AppException(ErrorCode.TOKEN_INVALID);
        }

        String accessToken =  jwtService.generateToken(user);

        // Lưu token mới vào cơ sở dữ liệu
        saveUserToken(user, accessToken, refresh_token);

        return TokenRespone.builder()
                .accesstoken(accessToken)
                .refreshtoken(refresh_token)
                .userid(user.getId())
                .build();
    }


    public String sendOTP(String email) {
        // Check if email exists
        User user = userService.findByEmail(email);
        // Check if user is active
        if (!user.isEnabled()) {
            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
        }

        // Generate OTP and send email
        String OTP = OTPGenerator.generateOTP();
        emailService.sendEmail(email, EMessage.TITLE_OTP.getValue(), EMessage.TEXT_EMAIL_OTP.getValue() + OTP);

        //
        user.setOTP(OTP);
        // Bước 1: Lấy thời gian hiện tại
        LocalDateTime currentTime = LocalDateTime.now();
        // Bước 2: Thêm 2 phút vào thời gian hiện tại
        LocalDateTime expirationTime = currentTime.plusMinutes(2);
        // Bước 3: Chuyển đổi LocalDateTime thành java.util.Date
        Date expirationDate = Date.from(expirationTime.atZone(ZoneId.systemDefault()).toInstant());

        user.setExpired(expirationDate);
        userRepository.save(user);

        // Return success response
        System.out.println("OTP sent to email: " + email);
        return "OTP sent successfully";

    }

    public void verifyOTP_register(String OTP, String email) {

        User user = userService.findByEmail(email);

        if (!OTP.equals(user.getOTP())) {
            throw new AppException(ErrorCode.OTP_INVALID);
        }

        //Cập nhật lại trang thái
        user.setStatus(true);
//        userService.saveUser(user);

        // Sau khi verify account thì tạo ra cart cho account đó
        Cart cart = new Cart();
        cart.setUser(user);
        cart.setCartItems(new ArrayList<>());
        cart.setTotalPrice(BigDecimal.valueOf(0));
        cart.setTotalItem(0);
        cartRepository.save(cart);

    }
    private void saveUserToken(User user, String jwtToken,String refreshToken) {
        var token = Token.builder()
                .user(user)
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(BigInteger.valueOf(user.getId()));
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    // đây là hàm su dụng cho tính năng quên mật khẩu
    public String forgotPassWord(ResetPasswordRequest request) {

        User user = userService.findByEmail(request.getEmail());

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new AppException(ErrorCode.PASS_WORD_NOT_MATCHED);
        }

        String encryptedPassword = passwordEncoder.encode(request.getPassword());
        user.setPassword(encryptedPassword);
        userService.saveUser(user);

        return "Password successfully changed";
    }

    public void checkOtpForgotPassWord(@Valid String otp, String email) {
        User user = userService.findByEmail(email);

        if (!otp.equals(user.getOTP())) {
            throw new AppException(ErrorCode.OTP_INVALID);
        }
    }

    public String changePassword(HttpServletRequest request, @Valid ChangePasswordRequest changePasswordRequest) {
        User user =  jwtUtil.getUserFromRequest(request);
        if (user == null) {
            throw new AppException(ErrorCode.USER_NOT_FOUND);
        }

        if (!passwordEncoder.matches(changePasswordRequest.getPassword(), user.getPassword())) {
            throw new AppException(ErrorCode.PASS_WORD_INCORRECT);
        }

        // Kiểm tra sự khớp của mật khẩu mới và mật khẩu xác nhận mới
        if (!changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmNewPassword())) {
            throw new AppException(ErrorCode.PASS_WORD_NOT_MATCHED);
        }
        user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));
        userRepository.save(user);

        return "Password updated successfully";
    }

}