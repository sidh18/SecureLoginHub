package com.example.loginapp.service;

import com.example.loginapp.model.user;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public user registerUser(String username, String password) {
        user user = new user();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        user.setCreatedVia("REGULAR");
        return userRepository.save(user);
    }

    public user registerUserFromSso(String username, String email, String firstName, String lastName) {
        user user = new user();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(java.util.UUID.randomUUID().toString())); // Random password
//        user.setEmail(email);
//        user.setFirstName(firstName);
//        user.setLastName(lastName);
        user.setRole("USER");
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        user.setCreatedVia("SSO");
        return userRepository.save(user);
    }

    public user findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}