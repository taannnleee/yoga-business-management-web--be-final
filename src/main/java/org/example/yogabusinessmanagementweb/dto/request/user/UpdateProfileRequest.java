package org.example.yogabusinessmanagementweb.dto.request.user;

import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.io.Serializable;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class UpdateProfileRequest implements Serializable {
    String fullname;
    String username;
    String imagePath;
    String firstName;
    String lastName;
    String gender;
    String email;
    String phone;
    String street;
    String city;
    String state;

    String dateOfBirth;
}
