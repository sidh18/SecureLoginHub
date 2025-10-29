package com.example.loginapp.service;

import com.example.loginapp.model.user;
import com.example.loginapp.config.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MiniOrangeSsoService {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Process user after SSO authentication and generate app JWT
     */
    public String processUserAfterSso(String username, String email, String firstName, String lastName) {
        System.out.println("🔄 Processing SSO user: " + username);

        // Use email as username if username is empty
        if (username == null || username.isEmpty()) {
            username = email;
        }

        if (username == null || username.isEmpty()) {
            throw new RuntimeException("No valid username or email provided");
        }

        // Check if user exists in our database
        user user = userService.findByUsername(username);

        // If user doesn't exist, create new user
        if (user == null) {
            user = userService.registerUserFromSso(username, email, firstName, lastName);
            System.out.println("✅ Created new user from SSO: " + username);
        } else {
            System.out.println("✅ Existing user logged in via SSO: " + username);
        }

        // Generate our own JWT token for the user
        String appJwtToken = jwtUtil.generateToken(username);
        System.out.println("✅ Generated JWT token for: " + username);

        return appJwtToken;
    }

    /**
     * Validate if SSO response contains required data
     */
    public boolean isValidSsoResponse(String username, String email) {
        return (username != null && !username.isEmpty()) || (email != null && !email.isEmpty());
    }
}