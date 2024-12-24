package org.example.yogabusinessmanagementweb.dto.response.comment;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.dto.response.user.UserCommentResponse;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CommentResponse {

    Long id;
    Integer ratePoint;
    String content;
    UserCommentResponse user;
    @JsonBackReference
    CommentResponse parentComment;
    @JsonManagedReference
    List<CommentResponse> replies;
    Date createdAt;
    Map<String, Map<String, String>>  currentVariant;
}
