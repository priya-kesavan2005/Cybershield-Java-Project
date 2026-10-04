package com.cybershield.controller;

import com.cybershield.model.User;
import com.cybershield.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.util.Map;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {
    @Mock
    private AuthService auth;

    @InjectMocks
    private AuthController controller;

    @Test
    void signupRejectsInvalidRequestBeforeCallingAuthService() throws Exception {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();
        try {
            MockMvc mvc = standaloneSetup(controller).setValidator(validator).build();

            mvc.perform(post("/api/auth/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"name":" ","email":"invalid","password":"short"}
                                    """))
                    .andExpect(status().isBadRequest());

            verifyNoInteractions(auth);
        } finally {
            validator.close();
        }
    }

    @Test
    void signupDelegatesRequestFieldsToAuthService() {
        User expected = new User();
        AuthController.Signup request =
                new AuthController.Signup("Name", "name@example.com", "secure-password");
        when(auth.signup("Name", "name@example.com", "secure-password")).thenReturn(expected);

        assertEquals(expected, controller.signup(request));
    }

    @Test
    void loginReturnsAuthServiceResponse() {
        AuthController.Login request = new AuthController.Login("name@example.com", "secure-password");
        Map<String, Object> expected = Map.of("token", "session-token");
        when(auth.login("name@example.com", "secure-password")).thenReturn(expected);

        assertEquals(expected, controller.login(request));
    }

    @Test
    void logoutDelegatesTokenToAuthService() {
        controller.logout("session-token");

        verify(auth).logout("session-token");
    }
}
