package org.example.yogabusinessmanagementweb.dto.response.teacher;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class TeacherResponse {
    Long id;

    String fullName;

    String introduction;

    String description;

    String email;

    String phoneNumber;

    int experienceYears;

    String profilePicture;
}
