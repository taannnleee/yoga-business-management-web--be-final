package org.example.yogabusinessmanagementweb.service.Impl;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.*;
import org.example.yogabusinessmanagementweb.common.mapper.CourseMapper;
import org.example.yogabusinessmanagementweb.dto.request.course.CourseCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.course.CourseResponse;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicCourseResponse;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.CoursesRepository;
import org.example.yogabusinessmanagementweb.repositories.TeacherRepository;
import org.example.yogabusinessmanagementweb.repositories.TopicRepository;
import org.example.yogabusinessmanagementweb.service.CoursesService;
import org.example.yogabusinessmanagementweb.service.TeacherService;
import org.example.yogabusinessmanagementweb.service.TopicService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@Service
public class CoursesServiceImpl implements CoursesService {
    CoursesRepository coursesRepository;
    CourseMapper courseMapper;
    TeacherService teacherService;
    TopicService topicService;

    TopicRepository topicRepository;
    TeacherRepository teacherRepository;

    @Override
    public CourseResponse addCourse(CourseCreationRequest courseCreationRequest) {
        Courses courses = courseMapper.toCourses(courseCreationRequest);
        Teacher teacher  =  teacherService.getTeacherByid(courseCreationRequest.getTeacherId());
        Topic topic  =  topicService.getTopicByid(courseCreationRequest.getTopicId());

        //set teacher và topic vào course
        courses.setTeacher(teacher);
        courses.setTopic(topic);
        coursesRepository.save(courses);
        return  courseMapper.toCoursesResponse(courses);
    }

    @Override
    public List<CourseResponse> getAllCourse() {
        List<Courses> coursesList =  coursesRepository.findAll();
        List<CourseResponse> courseResponses =  courseMapper.toCoursesResponseList(coursesList);
        return courseResponses;
    }

    @Override
    public List<TopicCourseResponse> getAllCourseWithTopic() {

        List<TopicCourseResponse> topicCourseResponses = new ArrayList<>();

        List<Topic> topics = topicRepository.findAll();
        for(Topic topic : topics){
            TopicCourseResponse topicCourseResponse = new TopicCourseResponse();
            topicCourseResponse.setTopicName(topic.getName());

            List<Courses> topicList = coursesRepository.findAllByTopic(topic);

            List<CourseResponse> courseResponses = courseMapper.toCoursesResponseList(topicList);
            topicCourseResponse.setCourse(courseResponses);

            topicCourseResponses.add(topicCourseResponse);
        }

        return topicCourseResponses;
    }

    @Override
    public Courses getCourse(String id) {
        Optional<Courses> coursesOptional = coursesRepository.findById(Long.valueOf(id));
        if(coursesOptional.isEmpty()){
            throw new AppException(ErrorCode.COURSE_NOT_FOUND);
        }
        Courses courses = coursesOptional.get();

        List<Sections> sectionsList =  courses.getSections();

        for(Sections sections : sectionsList){
            List<Lectures> lecturesList = sections.getLectures();
        }
        return courses;
    }

    @Override
    public List<CourseResponse> allTeacherCourses(String id) {
        Teacher teacher = teacherService.getTeacherByid(id);
        List<Courses> coursesList =  coursesRepository.findAllByTeacher(teacher);
        List<CourseResponse> courseResponseList = courseMapper.toCoursesResponseList(coursesList);
        return courseResponseList;
    }

    @Override
    public List<CourseResponse> getOutstandingCourses() {
        List<Courses> coursesList =  coursesRepository.findTop4ByOrderByIdAsc();
        List<CourseResponse> courseResponses =  courseMapper.toCoursesResponseList(coursesList);
        return courseResponses;
    }

    @Override
    public Courses getCourseByid(String id) {
        return coursesRepository.findById(Long.valueOf(id)).orElseThrow(()-> new AppException(ErrorCode.COURSE_NOT_FOUND));
    }
}
