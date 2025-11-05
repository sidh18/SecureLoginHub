package com.example.loginapp.service;

import com.example.loginapp.config.JwtUtil;
import com.example.loginapp.model.Organization;
import com.example.loginapp.model.user;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;
import java.util.List;

@Service
public class MiniOrangeSsoService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Checks if the SSO response has the minimum required user info.
     */
    public boolean isValidSsoResponse(String username, String email) {
        // We must have at least an email to identify the user
        return email != null && !email.isEmpty();
    }

    /**
     * This is the core "Find or Create" logic for all SSO logins.
     * It is now tenant-aware and requires an organizationId.
     *
     * @param username The username from the SSO provider
     * @param email The email from the SSO provider (used as the primary key)
     * @param firstName The first name from the SSO provider
     * @param lastName The last name from the SSO provider
     * @param organizationId The ID of the organization this user is logging into
     * @return An internal application JWT for the found or created user
     */
    public String processUserAfterSso(String username, String email, String firstName, String lastName, Long organizationId) throws Exception {

        if (organizationId == null) {
            // This should not be possible if the SSO config is set up correctly,
            // as all SSO configs should belong to an org.
            throw new Exception("SSO login failed: No organization context.");
        }

        if (email == null || email.isEmpty()) {
            throw new Exception("SSO login failed: Email is required from the SSO provider.");
        }

        // --- FIX: Robust "Find" Logic ---
        // We must find the user by EITHER email OR username *within this organization*.

        // 1. Try to find by email
        Optional<user> userOptional = userRepository.findByEmailAndOrganizationId(email, organizationId);

        // 2. If not found by email, try to find by username (if username was provided)
        if (userOptional.isEmpty() && username != null && !username.isEmpty()) {
            userOptional = userRepository.findByUsernameAndOrganizationId(username, organizationId);
        }
        // --- END FIX ---


        user userToLogin;

        if (userOptional.isPresent()) {
            // --- User Exists ---
            userToLogin = userOptional.get();

            // Update user's info from IdP
            userToLogin.setFirstName(firstName);
            userToLogin.setLastName(lastName);

            // If they were found by username, their email might be missing or different
            if (!email.equals(userToLogin.getEmail())) {
                // Check if the new email is already taken *globally* before updating
                if (userRepository.findByEmail(email).isPresent()) {
                    throw new Exception("SSO login failed: Email '" + email + "' is already in use by another account.");
                }
                userToLogin.setEmail(email);
            }
            // If they were found by email, their username might be missing or different
            if (username != null && !username.isEmpty() && !username.equals(userToLogin.getUsername())) {
                // Check if the new username is already taken *globally* before updating
                if (userRepository.findByUsername(username).isPresent()) {
                    throw new Exception("SSO login failed: Username '" + username + "' is already in use by another account.");
                }
                userToLogin.setUsername(username);
            }

            userToLogin = userRepository.save(userToLogin);

        } else {
            // --- Create New User ---

            // --- FIX: Pre-Create Global Uniqueness Check ---
            // Your 'user' model defines username and email as globally unique.
            // We must check this before trying to save.

            String newUsername = (username != null && !username.isEmpty()) ? username : email;

            if (userRepository.findByUsername(newUsername).isPresent()) {
                throw new Exception("SSO creation failed: Username '" + newUsername + "' is already taken.");
            }
            if (userRepository.findByEmail(email).isPresent()) {
                throw new Exception("SSO creation failed: Email '" + email + "' is already in use.");
            }
            // --- END GLOBAL CHECKS ---

            user newUser = new user();

            newUser.setUsername(newUsername);
            newUser.setEmail(email);
            newUser.setFirstName(firstName);
            newUser.setLastName(lastName);
            newUser.setRole("ROLE_USER"); // Default role for new SSO users
            newUser.setCreatedVia("SSO");
            newUser.setActive(true);

            // Generate a random, secure password (since they won't use it)
            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));

            // --- THIS IS THE CRITICAL STEP ---
            // Assign the user to the correct organization
            Organization org = organizationRepository.findById(organizationId)
                    .orElseThrow(() -> new Exception("Organization not found"));
            newUser.setOrganization(org);

            userToLogin = userRepository.save(newUser);
        }

        // --- Generate our internal JWT ---
        // We create CustomUserDetails to pass all info to the token generator
        var userDetails = new com.example.loginapp.security.CustomUserDetails(
                userToLogin.getUsername(),
                userToLogin.getPassword(),
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority(userToLogin.getRole())),
                userToLogin.getOrganization() != null ? userToLogin.getOrganization().getId() : null
        );

        return jwtUtil.generateToken(userDetails);
    }
}
