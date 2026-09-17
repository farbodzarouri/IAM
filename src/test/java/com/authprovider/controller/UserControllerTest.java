package com.authprovider.controller;

import com.authprovider.entity.User;
import com.authprovider.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    private MockMvc mockMvc;

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @BeforeEach
    public void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(userController).build();
    }

    @Test
    public void testGetAllUsers() throws Exception {
        User user = User.builder().id(1L).username("alice").build();
        when(userService.getAllUsers()).thenReturn(List.of(user));

        mockMvc.perform(get("/v1/api/users/all"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("alice"));
    }

    @Test
    public void testGetUserById() throws Exception {
        User user = User.builder().id(1L).username("bob").build();
        when(userService.getUserById(1L)).thenReturn(user);

        mockMvc.perform(get("/v1/api/users/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));
    }

    @Test
    public void testCreateUser() throws Exception {
        User user = User.builder().id(1L).username("charlie").password("pass").build();
        when(userService.saveUser(any(User.class))).thenReturn(user);

        mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"charlie\",\"password\":\"pass\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("charlie"));
    }

    @Test
    public void testUpdateUser() throws Exception {
        User user = User.builder().id(1L).username("updated").build();
        when(userService.saveUser(any(User.class))).thenReturn(user);

        mockMvc.perform(put("/v1/api/users/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"updated\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("updated"));
    }

    @Test
    public void testDeleteUser() throws Exception {
        mockMvc.perform(delete("/v1/api/users/1"))
                .andExpect(status().isOk());

        verify(userService).deleteUser(1L);
    }
}
