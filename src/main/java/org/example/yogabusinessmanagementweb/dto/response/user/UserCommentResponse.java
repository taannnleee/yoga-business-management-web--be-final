package org.example.yogabusinessmanagementweb.dto.response.user;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class UserCommentResponse {
    Long id;
    String fullname;
    String imagePath;
}
