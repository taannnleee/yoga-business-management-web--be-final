package org.example.yogabusinessmanagementweb.dto.response.lecture;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class LectureResponse {
    Long id;
    String title;
    String content;
    String videoPath;
    String image;
}
