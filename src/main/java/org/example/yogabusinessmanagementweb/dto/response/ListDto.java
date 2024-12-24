package org.example.yogabusinessmanagementweb.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class ListDto<T> {
    T content;
    int page;
    int pageSize;
    Long totalElements;
    int totalPages;

}
