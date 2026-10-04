package com.cybershield.controller;

import com.cybershield.model.User;
import com.cybershield.repo.UserRepository;
import com.cybershield.service.AuthService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final AuthService auth;
    private final UserRepository repo;

    public UserController(AuthService auth, UserRepository repo) {
        this.auth = auth;
        this.repo = repo;
    }

    @GetMapping("/me")
    public User me(@RequestHeader("X-Auth-Token") String token) {
        return auth.user(token);
    }

    record Update(String name, String phone, String avatar, Boolean alertsEnabled) {
    }

    @PutMapping("/me")
    public User update(@RequestHeader("X-Auth-Token") String token, @RequestBody Update request) {
        User user = auth.user(token);
        if (request.name() != null && !request.name().isBlank()) {
            user.setName(request.name().trim());
        }
        if (request.phone() != null) {
            user.setPhone(request.phone().trim());
        }
        if (request.avatar() != null) {
            user.setAvatar(request.avatar());
        }
        if (request.alertsEnabled() != null) {
            user.setAlertsEnabled(request.alertsEnabled());
        }
        user.touch();
        return repo.save(user);
    }
}
