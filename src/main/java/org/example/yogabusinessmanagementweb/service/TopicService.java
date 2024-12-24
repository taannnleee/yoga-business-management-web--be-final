package org.example.yogabusinessmanagementweb.service;

import org.example.yogabusinessmanagementweb.common.entities.Topic;
import org.example.yogabusinessmanagementweb.dto.request.topic.TopicCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicResponse;

import java.util.List;

public interface TopicService {
    Topic getTopicByid(String id);
    TopicResponse create(TopicCreationRequest topicCreationRequest);

    List<TopicResponse> getAllTopic();

    void deleteTopic(String id);

    TopicResponse updateTopic(String id, TopicCreationRequest topicCreationRequest);
}
