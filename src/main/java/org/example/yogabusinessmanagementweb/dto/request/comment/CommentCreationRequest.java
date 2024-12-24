package org.example.yogabusinessmanagementweb.dto.request.comment;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.util.Map;

@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CommentCreationRequest {

    String content;
    Integer ratePoint = null;
    String productId;
    // Mặc định parentComment = null
    String parentCommentId = null;
    Map<String, Map<String, String>>  currentVariant;
}