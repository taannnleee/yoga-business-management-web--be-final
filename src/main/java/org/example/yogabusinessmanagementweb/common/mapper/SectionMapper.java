package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.Sections;
import org.example.yogabusinessmanagementweb.dto.request.address.AddressRequest;
import org.example.yogabusinessmanagementweb.dto.request.section.SectionCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.address.AddressResponse;
import org.example.yogabusinessmanagementweb.dto.response.section.SectionResponse;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

import java.util.List;

@Mapper(componentModel = "spring")
public interface SectionMapper {
    SectionResponse toSectionResponse(Sections section);
    Sections toSection(SectionCreationRequest sectionCreationRequest);
    void updateSection(@MappingTarget Sections sections, SectionCreationRequest sectionCreationRequest );

    List<SectionResponse> toSectionResponseList(List<Sections> sections);
}
