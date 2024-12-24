package org.example.yogabusinessmanagementweb.common.mapper;

import jakarta.validation.constraints.Null;
import org.example.yogabusinessmanagementweb.common.entities.Comment;
import org.example.yogabusinessmanagementweb.common.entities.Topic;
import org.example.yogabusinessmanagementweb.dto.request.comment.CommentCreationRequest;
import org.example.yogabusinessmanagementweb.dto.request.topic.TopicCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentOrderResponse;
import org.example.yogabusinessmanagementweb.dto.response.comment.CommentResponse;
import org.example.yogabusinessmanagementweb.dto.response.topic.TopicResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import org.springframework.data.domain.Page;

import java.util.List;

@Mapper(componentModel = "spring", nullValuePropertyMappingStrategy = org.mapstruct.NullValuePropertyMappingStrategy.IGNORE)
public interface CommentMapper {
    @Mapping(target = "user", source = "user")
    @Mapping(target = "parentComment", ignore = true)  // Prevent mapping the parentComment directly
    @Mapping(target = "replies", ignore = true)
    CommentResponse toCommentResponse(Comment comment);

    @Mapping(target = "parentComment", ignore = true)
    @Mapping(target = "replies", ignore = true)
    List<CommentResponse> toCommentResponses(List<Comment> comments);

//    @Mapping(target = "user", source = "user")
//    @Mapping(target = "parentComment", ignore = true)  // Prevent mapping the parentComment directly
//    @Mapping(target = "replies", ignore = true)
    CommentOrderResponse toCommentOrderResponse(Comment comment);

    Comment toComment(CommentCreationRequest request);
}
