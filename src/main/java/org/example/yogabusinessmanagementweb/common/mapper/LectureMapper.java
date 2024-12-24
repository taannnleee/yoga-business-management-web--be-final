package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.entities.Lectures;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.dto.request.lecture.LectureCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.teacher.TeacherCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.lecture.LectureResponse;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;
@Mapper(componentModel = "spring")
public interface LectureMapper {
    LectureResponse toLectureResponse(Lectures lectures);
    Lectures toLecture(LectureCreationRequest lectureCreationRequest);
    void updateLecture(@MappingTarget Lectures lectures, LectureCreationRequest lectureCreationRequest );
}
