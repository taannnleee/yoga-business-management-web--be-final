package org.example.yogabusinessmanagementweb.dto.response.user;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.io.Serializable;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ProfileResponse implements Serializable {
    String fullname;
    String username;
    String email;
    String phone;
    String imagePath;
    String firstName;
    String lastName;
    String street;
    String city;
    String state;
    String gender;
    String dateOfBirth;
}
