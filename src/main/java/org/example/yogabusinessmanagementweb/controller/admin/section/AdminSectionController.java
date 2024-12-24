package org.example.yogabusinessmanagementweb.controller.admin.section;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.course.CourseCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.section.SectionCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.course.CourseResponse;
import org.example.yogabusinessmanagementweb.dto.response.section.SectionResponse;
import org.example.yogabusinessmanagementweb.service.CoursesService;
import org.example.yogabusinessmanagementweb.service.SectionsService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminSectionController {
    SectionsService sectionsService;

    @PostMapping("/add-section")
    public ApiResponse<?> createSection(@RequestBody SectionCreationRequest sectionCreationRequest) {
        SectionResponse sectionResponse = sectionsService.addSection(sectionCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "create section successfully",sectionResponse);
    }

    @GetMapping("/get-all-section-by-id-course/{id}")
    public ApiResponse<?> getAllSectionByIdCourse(@PathVariable String id) {
        List<SectionResponse> sectionResponse = sectionsService.getAllSectionByIdCourse(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get section by id course successfully",sectionResponse);
    }

    @GetMapping("/get-section/{id}")
    public ApiResponse<?> getSection(@PathVariable String id) {
        SectionResponse sectionResponse = sectionsService.getSection(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "get section  successfully",sectionResponse);
    }
}
