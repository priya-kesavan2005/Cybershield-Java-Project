package com.cybershield.controller;

import com.cybershield.model.User;
import com.cybershield.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    record Signup(
            @NotBlank String name,
            @NotBlank @Email String email,
            @NotBlank @Size(min = 8) String password) {
    }

    record Login(
            @NotBlank @Email String email,
            @NotBlank String password) {
    }

    @PostMapping("/signup")
    public User signup(@Valid @RequestBody Signup request) {
        return auth.signup(request.name(), request.email(), request.password());
    }

    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody Login request) {
        return auth.login(request.email(), request.password());
    }

    @PostMapping("/logout")
    public void logout(@RequestHeader("X-Auth-Token") String token) {
        auth.logout(token);
    }
}
