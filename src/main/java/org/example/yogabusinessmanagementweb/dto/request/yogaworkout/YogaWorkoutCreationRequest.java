package org.example.yogabusinessmanagementweb.dto.request.yogaworkout;


import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class YogaWorkoutCreationRequest {
    String name;
    String description;
    int duration;
    String imagePath;
    String instruction;
    Integer level;
    String videoPath;
}
