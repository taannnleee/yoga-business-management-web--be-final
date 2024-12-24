package org.example.yogabusinessmanagementweb.dto.request.user;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.util.Date;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class RegistrationRequest {
    @NotNull(message = "Username is required")
    String username;
    @NotNull(message = "Full name is required")
    String fullName;
    @NotNull(message = "firstName is required")
    String firstName;
    @NotNull(message = "lastName is required")
    String lastName;
    @NotNull(message = "Email is required")
    String email;
    @NotNull(message = "Phone is required")
    String phone;
    @NotNull(message = "Password is required")
    String password;
    @NotNull(message = "Confirm password is required")
    String confirmPassword;
    Date dateOfBirth;
    String gender;
    String status;

}
