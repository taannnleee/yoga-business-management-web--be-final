package org.example.yogabusinessmanagementweb.repositories;

import org.example.yogabusinessmanagementweb.common.entities.UserHasYogaWorkout;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserHasYogaWorkoutRepository extends JpaRepository<UserHasYogaWorkout, Long> {
}
