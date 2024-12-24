package org.example.yogabusinessmanagementweb.controller.admin.course;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.category.CategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.course.CourseCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.example.yogabusinessmanagementweb.dto.response.course.CourseResponse;
import org.example.yogabusinessmanagementweb.service.CategoryService;
import org.example.yogabusinessmanagementweb.service.CoursesService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminCourseController {
    CoursesService coursesService;

    @PostMapping("/add-course")
    public ApiResponse<?> createCourse(@RequestBody CourseCreationRequest courseCreationRequest) {
        CourseResponse addCourseResponse = coursesService.addCourse(courseCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "create course successfully",addCourseResponse);
    }

    @GetMapping("/all-course")
    public ApiResponse<?> getAllCourses() {
        List<CourseResponse> courseResponseList = coursesService.getAllCourse();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all courses successfully",courseResponseList);
    }
}
