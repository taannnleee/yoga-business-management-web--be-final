package org.example.yogabusinessmanagementweb.service.Impl;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.common.entities.Topic;
import org.example.yogabusinessmanagementweb.common.mapper.TeacherMapper;
import org.example.yogabusinessmanagementweb.dto.request.teacher.TeacherCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.TeacherRepository;
import org.example.yogabusinessmanagementweb.service.TeacherService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class TeacherServiceImpl implements TeacherService {
    TeacherRepository teacherRepository;
    TeacherMapper teacherMapper;

    @Override
    public TeacherResponse create(TeacherCreationRequest teacherCreationRequest) {
        Teacher teacher =  teacherMapper.toTeacher(teacherCreationRequest);
        teacherRepository.save(teacher);
        return teacherMapper.toTeacherResponse(teacher);
    }

    @Override
    public List<TeacherResponse> getAllTeacher() {
        List<Teacher> teachers = teacherRepository.findAll();
        List<TeacherResponse> list =  teacherMapper.toTeacherResponseList(teachers);
        return list;
    }

    @Override
    public void deleteTeacher(String id) {
        Optional<Teacher> teacher = teacherRepository.findById(Long.valueOf(id));
        if (teacher.isPresent()) {
            teacherRepository.delete(teacher.get());
        }
        else {
            throw new AppException(ErrorCode.TEACHER_NOT_FOUND);
        }
    }

    @Override
    public TeacherResponse updateTeacher(String id, TeacherCreationRequest teacherCreationRequest) {
        Optional<Teacher> teacherOptional = teacherRepository.findById(Long.valueOf(id));
        if(teacherOptional.isEmpty()){
            throw new AppException(ErrorCode.TEACHER_NOT_FOUND);
        }
        Teacher teacher = teacherOptional.get();

        teacherMapper.updateTeacher(teacher, teacherCreationRequest);
        teacherRepository.save(teacher);
        return teacherMapper.toTeacherResponse(teacher);
    }

    @Override
    public Teacher getTeacherByid(String id) {
        return teacherRepository.findById(Long.valueOf(id)).orElseThrow(()-> new AppException(ErrorCode.TEACHER_NOT_FOUND));
    }
}
