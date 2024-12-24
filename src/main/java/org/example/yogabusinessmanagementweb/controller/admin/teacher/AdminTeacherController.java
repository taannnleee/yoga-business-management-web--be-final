package org.example.yogabusinessmanagementweb.controller.admin.teacher;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.teacher.TeacherCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.topic.TopicCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicResponse;
import org.example.yogabusinessmanagementweb.service.TeacherService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminTeacherController {
    TeacherService teacherService;

    @PostMapping("/add-teacher")
    public ApiResponse<?> addTeacher(@RequestBody TeacherCreationRequest teacherCreationRequest) {
        TeacherResponse teacherResponse = teacherService.create(teacherCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "create teacher success",teacherResponse );
    }

    @GetMapping("/all-teachers")
    public ApiResponse<?> getAllTeacher() {
        List<TeacherResponse> list = teacherService.getAllTeacher();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all teacher success",list );
    }

    @DeleteMapping("/delete-teacher/{id}")
    public ApiResponse<?> deleteTeacher(@PathVariable String id) {
        teacherService.deleteTeacher(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "delete teacher success" );
    }

    @PutMapping("/update-teacher/{id}")
    public ApiResponse<?> updateTeacher(@PathVariable String id,@RequestBody TeacherCreationRequest teacherCreationRequest) {
        TeacherResponse teacherResponse =  teacherService.updateTeacher(id,teacherCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "update teacher success",teacherResponse );
    }

}
