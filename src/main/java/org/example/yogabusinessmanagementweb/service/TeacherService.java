package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.dto.request.teacher.TeacherCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;

import java.util.List;

public interface TeacherService {
    Teacher getTeacherByid(String id);
    TeacherResponse create(TeacherCreationRequest teacherCreationRequest);

    List<TeacherResponse> getAllTeacher();

    void deleteTeacher(String id);

    TeacherResponse updateTeacher(String id, TeacherCreationRequest teacherCreationRequest);
}
