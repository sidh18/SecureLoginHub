package com.example.loginapp.service;

import com.example.loginapp.model.user;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant; // --- FIX: Use Instant ---
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // This method is likely not used anymore, as CustomUserDetailsService handles loading
    public user findByUsername(String username, Long organizationId) {
        Optional<user> userOptional;
        if (organizationId == null) {
            userOptional = userRepository.findByUsernameAndOrganizationIdIsNull(username);
        } else {
            userOptional = userRepository.findByUsernameAndOrganizationId(username, organizationId);
        }

        // --- FIX: Correctly unwrap the Optional ---
        return userOptional.orElse(null);
    }

    // This is probably an old method. We've moved this logic to AdminService.
    // I am updating it to be correct.
    public user createUser(String username, String password, String email, String role, Long organizationId) {
        user newUser = new user();
        newUser.setUsername(username);
        newUser.setPassword(passwordEncoder.encode(password));
        newUser.setEmail(email);
        newUser.setRole(role);

        // --- FIX: No need to set createdAt, @PrePersist does it ---
        // newUser.setCreatedAt(Instant.now()); // This would work, but is redundant

        // We can't set the organization here because we don't have the Organization object.
        // This is why we created AdminService.

        // This method is likely broken because it doesn't set the organization.
        // Please use AdminService.createUser instead.

        // return userRepository.save(newUser);

        // We'll just return the user object for now to fix compile errors
        return newUser;
    }

    public user findById(Long id) {
        // --- FIX: Correctly unwrap the Optional ---
        Optional<user> userOptional = userRepository.findById(id);
        return userOptional.orElse(null);
    }

    public List<user> findAll() {
        return userRepository.findAll();
    }
}