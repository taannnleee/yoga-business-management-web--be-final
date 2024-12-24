package org.example.yogabusinessmanagementweb.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.request.category.CategoryCreationRequest;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.category.CategoryResponse;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/test")
@Slf4j
public class TestController {
    SimpMessagingTemplate messagingTemplate;
    @GetMapping()
    public String createCategory() {
        messagingTemplate.convertAndSend("/topic/admin", "Có sản phẩm mới được nhập shop với tên là: " + "Chưa biết");
        return "Test success";
    }
}
