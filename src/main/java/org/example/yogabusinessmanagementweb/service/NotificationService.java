package org.example.yogabusinessmanagementweb.service;

import jakarta.servlet.http.HttpServletRequest;
import org.example.yogabusinessmanagementweb.common.entities.Notification;

import java.util.List;

public interface NotificationService {
    Notification findById(String id);
    List<Notification> getAllNotificationByUser(HttpServletRequest request);

    Notification changeStatus(HttpServletRequest request, String id);
}
