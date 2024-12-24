package org.example.yogabusinessmanagementweb.dto.request.user;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.io.Serializable;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)

public class LoginRequest implements Serializable {
    @NotNull(message = "Username is required")
    String username;
    @NotNull(message = "Password is required")
    String password;
}
