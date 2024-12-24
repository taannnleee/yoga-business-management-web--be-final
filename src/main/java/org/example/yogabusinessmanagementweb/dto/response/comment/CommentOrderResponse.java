package org.example.yogabusinessmanagementweb.dto.response.comment;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.util.Map;

@Getter
@Setter
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class CommentOrderResponse {

    Long id;
    String content;
    int ratePoint;
    Long userId;  // Thay vì toàn bộ đối tượng User, chỉ lấy ID
    Long productId;
}
