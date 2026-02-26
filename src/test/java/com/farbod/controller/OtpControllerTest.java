package com.farbod.controller;

import com.farbod.entity.User;
import com.farbod.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    public void testGenerateSecret() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");

        when(userService.getUserById(1L)).thenReturn(user);
        when(userService.saveUser(any(User.class))).thenReturn(user);

        mockMvc.perform(post("/api/otp/generate/1"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser
    public void testValidateOtp_NoSecret() throws Exception {
        User user = new User();
        user.setId(1L);
        // No secret

        when(userService.getUserById(1L)).thenReturn(user);

        String json = "{\"userId\": 1, \"otp\": 123456}";

        mockMvc.perform(post("/api/otp/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest());
    }
}
