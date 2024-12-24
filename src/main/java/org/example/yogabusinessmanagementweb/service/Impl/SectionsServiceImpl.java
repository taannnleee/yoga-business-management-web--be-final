package org.example.yogabusinessmanagementweb.service.Impl;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Courses;
import org.example.yogabusinessmanagementweb.common.entities.Sections;
import org.example.yogabusinessmanagementweb.common.mapper.SectionMapper;
import org.example.yogabusinessmanagementweb.dto.request.section.SectionCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.section.SectionResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.CoursesRepository;
import org.example.yogabusinessmanagementweb.repositories.SectionsRepository;
import org.example.yogabusinessmanagementweb.service.CoursesService;
import org.example.yogabusinessmanagementweb.service.SectionsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class SectionsServiceImpl implements SectionsService {
    SectionsRepository sectionsRepository;
    SectionMapper sectionMapper;
    CoursesRepository coursesRepository;
    CoursesService coursesService;

    @Override
    public SectionResponse addSection(SectionCreationRequest sectionCreationRequest) {
        Sections sections = sectionMapper.toSection(sectionCreationRequest);

        //tìm course
        Courses courses = coursesService.getCourseByid(String.valueOf(sectionCreationRequest.getIdCourse()));
        courses.getSections().add(sections);

        // luu course va section
        coursesRepository.save(courses);
        return sectionMapper.toSectionResponse(sections);
    }

    @Override
    public List<SectionResponse> getAllSectionByIdCourse(String id) {
        Courses courses =  coursesService.getCourseByid(id);
        List<Sections> sectionsList = courses.getSections();
        return (sectionMapper.toSectionResponseList(sectionsList));
    }

    @Override
    public SectionResponse getSection(String id) {
        Sections sections  =  getSectionsByid(id);
        return sectionMapper.toSectionResponse(sections);
    }

    @Override
    public Sections getSectionsByid(String id) {
        return sectionsRepository.findById(Long.valueOf(id)).orElseThrow(()-> new AppException(ErrorCode.SECTION_NOT_FOUND));
    }
}
