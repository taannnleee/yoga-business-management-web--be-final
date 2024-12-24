package org.example.yogabusinessmanagementweb.dto.request.user;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ChangePasswordRequest {
    @NotNull(message = "Password is required")
    String password;

    @NotNull(message = "New password is required")
    String newPassword;

    @NotNull(message = "Confirm new password is required")
    String confirmNewPassword;
}
