package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.Sections;
import org.example.yogabusinessmanagementweb.dto.request.section.SectionCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.section.SectionResponse;

import java.util.List;

public interface SectionsService {
    Sections getSectionsByid(String id);
    SectionResponse addSection(SectionCreationRequest sectionCreationRequest);

    List<SectionResponse>  getAllSectionByIdCourse(String id);

    SectionResponse getSection(String id);
}
