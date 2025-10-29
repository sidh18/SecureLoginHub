package com.example.loginapp.service;

import com.example.loginapp.model.user;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AdminService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public List<user> getAllUsers() {
        return userRepository.findAll();
    }

    public user getUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public user createUser(String username, String password, String email,
                           String firstName, String lastName, String role) {
        user user = new user();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
//        user.setEmail(email);
//        user.setFirstName(firstName);
//        user.setLastName(lastName);
        user.setRole(role != null ? role : "USER");
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        user.setCreatedVia("ADMIN");
        return userRepository.save(user);
    }

    public user updateUser(Long id, String username, String email,
                           String firstName, String lastName, String role, Boolean active) {
        user user = userRepository.findById(id).orElse(null);
        if (user == null) {
            return null;
        }

        if (username != null && !username.isEmpty()) {
            user.setUsername(username);
        }
//        if (email != null) {
//            user.setEmail(email);
//        }
//        if (firstName != null) {
//            user.setFirstName(firstName);
//        }
//        if (lastName != null) {
//            user.setLastName(lastName);
//        }
        if (role != null) {
            user.setRole(role);
        }
        if (active != null) {
            user.setActive(active);
        }

        return userRepository.save(user);
    }

    public boolean deleteUser(Long id) {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public user resetPassword(Long id, String newPassword) {
        user user = userRepository.findById(id).orElse(null);
        if (user == null) {
            return null;
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        return userRepository.save(user);
    }
}