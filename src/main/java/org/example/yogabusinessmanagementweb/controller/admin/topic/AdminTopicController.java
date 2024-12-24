package org.example.yogabusinessmanagementweb.controller.admin.topic;

import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.topic.TopicCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.teacher.TeacherResponse;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicResponse;
import org.example.yogabusinessmanagementweb.service.TopicService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminTopicController {
    TopicService topicService;

    @PostMapping("/add-topic")
    public ApiResponse<?> createTopic(@RequestBody TopicCreationRequest topicCreationRequest) {
        TopicResponse topicResponse = topicService.create(topicCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "create topic success",topicResponse );
    }

    @GetMapping("/all-topic")
    public ApiResponse<?> getAllTopic() {
        List<TopicResponse> list = topicService.getAllTopic();
        return new ApiResponse<>(HttpStatus.OK.value(), "get all topic success",list );
    }

    @DeleteMapping("/delete-topic/{id}")
    public ApiResponse<?> deleteTopic(@PathVariable String id) {
        topicService.deleteTopic(id);
        return new ApiResponse<>(HttpStatus.OK.value(), "delete topic success" );
    }

    @PutMapping("/update-topic/{id}")
    public ApiResponse<?> updateTopic(@PathVariable String id,@RequestBody TopicCreationRequest topicCreationRequest) {
        TopicResponse topicResponse =  topicService.updateTopic(id,topicCreationRequest);
        return new ApiResponse<>(HttpStatus.OK.value(), "update topic success",topicResponse );
    }
}
