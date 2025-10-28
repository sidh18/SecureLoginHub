package com.example.loginapp;

import com.example.loginapp.config.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest
class LoginAppApplicationTests {

    // MOCK JwtUtil – this stops the NPE
    @MockBean
    private JwtUtil jwtUtil;

    @Test
    void contextLoads() {
        // No body – just loading the context
    }
}