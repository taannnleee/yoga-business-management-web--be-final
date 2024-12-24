package org.example.yogabusinessmanagementweb.common.mapper;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.request.teacher.TeacherCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

import java.util.List;

@Mapper(componentModel = "spring")
public interface TeacherMapper {
    TeacherResponse toTeacherResponse(Teacher teacher);
    Teacher toTeacher(TeacherCreationRequest teacher);
    void updateTeacher(@MappingTarget Teacher teacher, TeacherCreationRequest teacherRequest );
    // map list
    List<TeacherResponse> toTeacherResponseList(List<Teacher> teachers);
    List<Teacher> toTeacherList(List<TeacherCreationRequest> teacherRequests);
}
