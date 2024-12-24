package org.example.yogabusinessmanagementweb.dto.request.course;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CourseCreationRequest {
    String name;
    String instruction;
    String description;
    String duration;
    String imagePath;
    int level;
    String videoPath;
    BigDecimal price;
    String teacherId;
    String topicId;

}
