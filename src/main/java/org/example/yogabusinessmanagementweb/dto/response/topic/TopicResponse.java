package org.example.yogabusinessmanagementweb.dto.response.topic;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class TopicResponse {
    Long id;
    String name;
    String description;
}
