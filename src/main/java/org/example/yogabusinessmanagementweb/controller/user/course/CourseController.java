package org.example.yogabusinessmanagementweb.controller.user.course;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Courses;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.course.CourseResponse;
import org.example.yogabusinessmanagementweb.dto.response.section.SectionResponse;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicCourseResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.*;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/course")
@Slf4j
public class CourseController {
    UserService userService;
    UserRepository userRepository;
    EmailService emailService;
    AuthencationService authencationService;
    ProductService productService;
    CartService cartService;
    OrderService orderService;
    CoursesService coursesService;
    SectionsService sectionsService;

    @GetMapping("/all-course")
    public ApiResponse<?> getAllCourses() {
        List<TopicCourseResponse> courseResponseList = coursesService.getAllCourseWithTopic();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all courses successfully",courseResponseList);
    }

    @GetMapping("/get-all-section-by-id-course/{id}")
    public ApiResponse<?> getAllSectionByIdCourse(@PathVariable String id) {
        List<SectionResponse> sectionResponse = sectionsService.getAllSectionByIdCourse(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get section by id course successfully",sectionResponse);
    }

    @GetMapping("/get-course/{id}")
    public ApiResponse<?> getCourse(@PathVariable String id) {
        Courses courses = coursesService.getCourse(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get courses by id  successfully",courses);
    }

    @GetMapping("/all-teacher-courses/{id}")
    public ApiResponse<?> allTeacherCourses(@PathVariable String id) {
        List<CourseResponse> allTeacherCourses = coursesService.allTeacherCourses(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get all teacher courses successfully",allTeacherCourses);
    }

    // get các khóa học nổi bậc. Get 8 khóa học
    @GetMapping("/get-outstanding-courses")
    public ApiResponse<?> getOutstandingCourses() {
        List<CourseResponse> list = coursesService.getOutstandingCourses();
        return new ApiResponse<>(HttpStatus.OK.value(), "get courses outstanding successfully",list);
    }

}
