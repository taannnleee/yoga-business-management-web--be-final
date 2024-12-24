package org.example.yogabusinessmanagementweb.controller.user.teacher;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.lecture.LectureResponse;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.example.yogabusinessmanagementweb.service.LecturesService;
import org.example.yogabusinessmanagementweb.service.TeacherService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/teacher")
@Slf4j
public class TeacherController {
    TeacherService teacherService;

    @GetMapping("/all-teachers")
    public ApiResponse<?> getAllTeacher() {
        List<TeacherResponse> list = teacherService.getAllTeacher();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all teacher success",list );
    }

    @GetMapping("/get-teacher/{id}")
    public ApiResponse<?> getAllTeacher(@PathVariable String id) {
        Teacher teacher = teacherService.getTeacherByid(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get teacher by id success",teacher );
    }
}
