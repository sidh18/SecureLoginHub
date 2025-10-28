package com.example.loginapp.controller;

import com.example.loginapp.service.CustomUserDetailsService;
import com.example.loginapp.config.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @GetMapping("/test")
    public ResponseEntity<?> test() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "API is working!");
        response.put("timestamp", new Date().toString());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/secure")
    public ResponseEntity<?> secureEndpoint() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "You have accessed a secure endpoint!");
        response.put("timestamp", new Date().toString());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            boolean isValid = jwtUtil.validateToken(token, userDetails);

            Map<String, Object> response = new HashMap<>();
            response.put("valid", isValid);
            response.put("username", username);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
        }
    }

    @GetMapping("/token-info")
    public ResponseEntity<?> getTokenInfo(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);
            Date expiration = jwtUtil.extractExpiration(token);

            Map<String, Object> response = new HashMap<>();
            response.put("username", username);
            response.put("expiresAt", expiration);
            response.put("isValid", jwtUtil.validateToken(token));

            long timeLeft = expiration.getTime() - System.currentTimeMillis();
            response.put("timeLeftSeconds", timeLeft / 1000);
            response.put("timeLeftMinutes", timeLeft / 60000);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
        }
    }
}
