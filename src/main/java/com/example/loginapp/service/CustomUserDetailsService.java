package com.example.loginapp.service;

import com.example.loginapp.config.TenantContext;
import com.example.loginapp.model.user;
import com.example.loginapp.repository.UserRepository;
import com.example.loginapp.security.CustomUserDetails; // Import our new class
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * This method is now "tenant-aware".
     * It's called by Spring Security during a FORM LOGIN.
     * It checks the TenantContext to see which domain the user is on.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. Get the current tenant ID from our filter
        Long orgId = TenantContext.getCurrentOrganizationId();

        Optional<user> userOptional;

        if (orgId == null) {
            // --- SUPERADMIN LOGIN FLOW ---
            // This is "superadmin.localhost".
            // We only look for users with no organization.
            userOptional = userRepository.findByUsernameAndOrganizationIdIsNull(username);

            if (userOptional.isPresent() && !userOptional.get().getRole().equals("ROLE_SUPER_ADMIN")) {
                // This is a safety check. Only superadmins can log in here.
                throw new UsernameNotFoundException("Access denied for this domain.");
            }

        } else {
            // --- TENANT LOGIN FLOW ---
            // This is "acme.localhost" or "globex.localhost".
            // We look for the user *within that specific organization*.
            userOptional = userRepository.findByUsernameAndOrganizationId(username, orgId);
        }

        // 2. If user not found in the correct tenant, reject them.
        user user = userOptional.orElseThrow(() ->
                new UsernameNotFoundException("User not found: " + username + " for this organization.")
        );

        // 3. Return our new CustomUserDetails object
        return new CustomUserDetails(user);
    }
}
