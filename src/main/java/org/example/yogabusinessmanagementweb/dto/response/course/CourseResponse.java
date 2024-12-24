package org.example.yogabusinessmanagementweb.dto.response.course;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.common.entities.Topic;

import java.math.BigDecimal;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CourseResponse {
    Long id;
    String name;
    String instruction;
    String description;
    String duration;
    String imagePath;
    int level;
    String videoPath;
    BigDecimal price;
//    Teacher teacher;
//    Topic topic;
}
