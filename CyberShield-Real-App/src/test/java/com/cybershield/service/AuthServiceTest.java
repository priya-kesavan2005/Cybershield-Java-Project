package com.cybershield.service;

import com.cybershield.model.User;
import com.cybershield.repo.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    @Mock
    private UserRepository users;

    @InjectMocks
    private AuthService service;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Test
    void signupNormalizesEmailAndHashesPassword() {
        when(users.findByEmail(" User@Example.com ")).thenReturn(Optional.empty());
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.signup("  Priya  ", " User@Example.com ", "secure-password");

        assertEquals("Priya", result.getName());
        assertEquals("user@example.com", result.getEmail());
        assertNotEquals("secure-password", result.getPasswordHash());
        assertTrue(encoder.matches("secure-password", result.getPasswordHash()));
    }

    @Test
    void signupRejectsAlreadyRegisteredEmail() {
        when(users.findByEmail("used@example.com")).thenReturn(Optional.of(new User()));

        assertThrows(IllegalArgumentException.class,
                () -> service.signup("User", "used@example.com", "secure-password"));

        verify(users, never()).save(any(User.class));
    }

    @Test
    void loginReturnsTokenAndUserForValidCredentials() {
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(user.getPasswordHash()).thenReturn(encoder.encode("secure-password"));
        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        Map<String, Object> result = service.login(" User@Example.com ", "secure-password");

        assertTrue(result.get("token") instanceof String);
        assertEquals(user, result.get("user"));
    }

    @Test
    void loginRejectsUnknownEmailAndIncorrectPassword() {
        when(users.findByEmail("missing@example.com")).thenReturn(Optional.empty());
        assertThrows(IllegalArgumentException.class,
                () -> service.login("missing@example.com", "password"));

        User user = org.mockito.Mockito.mock(User.class);
        when(user.getPasswordHash()).thenReturn(encoder.encode("correct-password"));
        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        assertThrows(IllegalArgumentException.class,
                () -> service.login("user@example.com", "incorrect-password"));
    }

    @Test
    void logoutInvalidatesSessionToken() {
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(user.getPasswordHash()).thenReturn(encoder.encode("secure-password"));
        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(users.findById(42L)).thenReturn(Optional.of(user));
        Map<String, Object> result = service.login("user@example.com", "secure-password");
        String token = (String) result.get("token");

        assertEquals(user, service.user(token));
        service.logout(token);

        assertThrows(IllegalArgumentException.class, () -> service.user(token));
    }
}
