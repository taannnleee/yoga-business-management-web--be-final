package org.example.yogabusinessmanagementweb.common.mapper;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.Courses;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.request.course.CourseCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.dto.response.course.CourseResponse;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicCourseResponse;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

import java.util.List;

@Mapper(componentModel = "spring")
public interface CourseMapper {
    CourseResponse toCoursesResponse(Courses courses);
    Courses toCourses(CourseCreationRequest courseCreationRequest);
    void updateCourses(@MappingTarget Courses courses, CourseCreationRequest courseCreationRequest );

    List<CourseResponse> toCoursesResponseList(List<Courses> courses);

}
