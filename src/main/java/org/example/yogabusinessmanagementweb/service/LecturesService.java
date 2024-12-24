package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.dto.request.lecture.LectureCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.lecture.LectureResponse;

import java.util.List;

public interface LecturesService {
    LectureResponse addLecture(LectureCreationRequest lectureCreationRequest);

    List<LectureResponse> getAllLectureByIdSection(String id);

    LectureResponse getLectureById(String id);
}
