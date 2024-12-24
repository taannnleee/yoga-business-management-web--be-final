package org.example.yogabusinessmanagementweb.common.mapper;

import org.example.yogabusinessmanagementweb.dto.response.ListDto;
import org.springframework.data.domain.Page;

import java.util.List;

public interface GenericMapper {
    // Đổi phương thức này thành tĩnh
    static <E, R> ListDto<List<R>> toListDto(List<R> responses, Page<E> page) {
        return ListDto.<List<R>>builder()
                .content(responses)
                .page(page.getNumber()+1)
                .pageSize(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .build();
    }
}
