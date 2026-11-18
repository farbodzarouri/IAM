package com.authprovider.controller;

import com.authprovider.entity.User;
import com.authprovider.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class OtpControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Test
    @WithMockUser
    public void testGenerateSecretByUsername() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");

        when(userService.findAllByUsernameIgnoreCase("testuser")).thenReturn(List.of(user));
        when(userService.saveUser(any(User.class))).thenReturn(user);

        mockMvc.perform(post("/v1/api/otp/generate/testuser"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser
    public void testGenerateSecret_NotFound() throws Exception {
        when(userService.findAllByUsernameIgnoreCase("missing")).thenReturn(List.of());

        mockMvc.perform(post("/v1/api/otp/generate/missing"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testValidateOtp_NoSecret() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");

        when(userService.findAllByUsernameIgnoreCase("testuser")).thenReturn(List.of(user));

        String json = "{\"username\": \"testuser\", \"otp\": \"123456\"}";

        mockMvc.perform(post("/v1/api/otp/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.status").value("NOT_ENROLLED"));
    }

    @Test
    public void testValidateOtp_InvalidPayload() throws Exception {
        mockMvc.perform(post("/v1/api/otp/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\": \"testuser\", \"otp\": \"not-digits\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.status").value("INVALID_REQUEST"));
    }
}
