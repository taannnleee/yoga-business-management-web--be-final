package org.example.yogabusinessmanagementweb.dto.request.user;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ResetPasswordRequest {
//    private String secretKey;
    @NotNull(message = "Email is required")
    String email;
    @NotNull(message = "Password is required")
    String password;
    @NotNull(message = "Confirm password is required")
    String confirmPassword;
}
