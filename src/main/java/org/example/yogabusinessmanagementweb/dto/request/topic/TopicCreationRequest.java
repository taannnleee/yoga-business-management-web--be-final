package org.example.yogabusinessmanagementweb.dto.request.topic;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class TopicCreationRequest {
    String name;
    String description;
}
