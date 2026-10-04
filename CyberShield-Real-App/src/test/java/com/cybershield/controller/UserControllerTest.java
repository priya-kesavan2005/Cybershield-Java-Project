package com.cybershield.controller;

import com.cybershield.model.User;
import com.cybershield.repo.UserRepository;
import com.cybershield.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {
    @Mock
    private AuthService auth;
    @Mock
    private UserRepository repository;

    private UserController controller;
    private User user;

    @BeforeEach
    void setUp() {
        controller = new UserController(auth, repository);
        user = new User();
        user.setName("Initial");
        user.setPhone("111");
        when(auth.user("token")).thenReturn(user);
    }

    @Test
    void meReturnsAuthenticatedUser() {
        assertEquals(user, controller.me("token"));
    }

    @Test
    void updateTrimsNameAndPhoneAndAppliesOptionalFields() {
        when(repository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        UserController.Update request =
                new UserController.Update("  Updated  ", "  222  ", "avatar.png", false);

        User result = controller.update("token", request);

        assertEquals("Updated", result.getName());
        assertEquals("222", result.getPhone());
        assertEquals("avatar.png", result.getAvatar());
        assertFalse(result.isAlertsEnabled());
        verify(repository).save(user);
    }

    @Test
    void updateIgnoresBlankNameAndPreservesUnsetFields() {
        when(repository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = controller.update("token", new UserController.Update("  ", null, null, null));

        assertEquals("Initial", result.getName());
        assertEquals("111", result.getPhone());
        assertTrue(result.isAlertsEnabled());
    }
}
