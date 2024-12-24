package org.example.yogabusinessmanagementweb.dto.request.teacher;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class TeacherCreationRequest {
    String fullName;

    String introduction;

    String description;

    String email;

    String phoneNumber;

    int experienceYears;

    String profilePicture;
}
