package org.example.yogabusinessmanagementweb.dto.request.lecture;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class LectureCreationRequest {
    Long idSection; // để biết muốn lưu vài học vào chương nào
    String title;
    String content;
    String videoPath;
    String duration;
    String image;
}
