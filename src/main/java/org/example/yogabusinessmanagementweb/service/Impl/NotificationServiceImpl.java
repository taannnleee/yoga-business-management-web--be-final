package org.example.yogabusinessmanagementweb.service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.yogabusinessmanagementweb.common.entities.Address;
import org.example.yogabusinessmanagementweb.common.entities.Notification;
import org.example.yogabusinessmanagementweb.common.entities.User;
import org.example.yogabusinessmanagementweb.common.util.JwtUtil;
import org.example.yogabusinessmanagementweb.exception.AppException;
import org.example.yogabusinessmanagementweb.exception.ErrorCode;
import org.example.yogabusinessmanagementweb.repositories.NotificationRepository;
import org.example.yogabusinessmanagementweb.service.NotificationService;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class NotificationServiceImpl implements NotificationService {
    JwtUtil jwtUtil;
    NotificationRepository notificationRepository;
    @Override
    public List<Notification> getAllNotificationByUser(HttpServletRequest request) {
        User user =  jwtUtil.getUserFromRequest(request);
        List<Notification> list =  notificationRepository.findAllByUser(user);
        Collections.reverse(list);
        return  list;
    }

    @Override
    public Notification changeStatus(HttpServletRequest request, String id) {
        Notification notification =  findById(id);
        notification.setRead(true);
        notificationRepository.save(notification);
        return notification;
    }

    @Override
    public Notification findById(String id) {
        return notificationRepository.findById(Long.valueOf(id)).orElseThrow(()-> new AppException(ErrorCode.NOTIFICATION_NOT_FOUND));
    }
}
