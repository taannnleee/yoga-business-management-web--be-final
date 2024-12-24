package org.example.yogabusinessmanagementweb.controller.admin.user;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.yogabusinessmanagementweb.dto.response.ApiResponse;
import org.example.yogabusinessmanagementweb.repositories.UserRepository;
import org.example.yogabusinessmanagementweb.service.Impl.AuthencationService;
import org.example.yogabusinessmanagementweb.service.UserService;
import org.example.yogabusinessmanagementweb.service.EmailService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/admin")
@Slf4j
public class AdminUserController {

    UserService userService;
    UserRepository userRepository;
    EmailService emailService;
    AuthencationService authencationService;

    @GetMapping("/getAllUser")
    public ApiResponse<?> getAllUser() {
        return new ApiResponse<>(HttpStatus.OK.value(), "Get all user success", userService.getAllUser());
    }

    @GetMapping("getUserById/{id}")
    public ApiResponse<?> getUserById(@Valid @PathVariable Integer id) {
        return new ApiResponse<>(HttpStatus.OK.value(), "Get all user success", userService.findUserById(String.valueOf(id)));
    }
}
