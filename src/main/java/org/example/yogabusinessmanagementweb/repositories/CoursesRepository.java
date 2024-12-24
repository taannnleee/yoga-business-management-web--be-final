package org.example.yogabusinessmanagementweb.repositories;

import org.example.yogabusinessmanagementweb.common.entities.Courses;
import org.example.yogabusinessmanagementweb.common.entities.Teacher;
import org.example.yogabusinessmanagementweb.common.entities.Topic;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CoursesRepository  extends JpaRepository<Courses, Long> {
    List<Courses> findAllByTopic(Topic topic);
    List<Courses> findAllByTeacher(Teacher teacher);

    List<Courses> findTop4ByOrderByIdAsc();
}
