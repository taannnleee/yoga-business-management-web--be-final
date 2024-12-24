package org.example.yogabusinessmanagementweb.controller.user.notification;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.common.entities.Notification;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.dto.response.lecture.LectureResponse;
import org.example.yogabusinessmanagementweb.service.NotificationService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/notification")
@Slf4j
public class NotificationController {
    NotificationService notificationService;

    // lấy thông báo của user
    @GetMapping("/get-all-of-user")
    public ApiResponse<?> getAllNotificationByUser(HttpServletRequest request) {
        List<Notification> list = notificationService.getAllNotificationByUser(request);
        return new ApiResponse<>(HttpStatus.OK.value(), "get all notification by id successfully",list);
    }

    //sua lại là trạng thái đã đọc
    @GetMapping("/change-status/{id}")
    public ApiResponse<?> changeStatus(HttpServletRequest request, @PathVariable String id) {
        Notification notification = notificationService.changeStatus(request,id);
        return new ApiResponse<>(HttpStatus.OK.value(), "change status notification successfully",notification);
    }

}
