package org.example.yogabusinessmanagementweb.dto.request.section;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class SectionCreationRequest {
    Long idCourse; // id của khóa học
    String title;
}
