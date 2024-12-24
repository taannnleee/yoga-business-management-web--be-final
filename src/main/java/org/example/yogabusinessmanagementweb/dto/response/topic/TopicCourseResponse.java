package org.example.yogabusinessmanagementweb.dto.response.topic;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.course.CourseResponse;

import java.util.List;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class TopicCourseResponse {
    String topicName;
    List<CourseResponse> course;
}
