package com.example.loginapp.config;

import com.example.loginapp.model.Organization;
import com.example.loginapp.model.user;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {

        // 1. Create the Superadmin Organization (a special one)
        // This is a "dummy" org for the superadmin subdomain
        if (organizationRepository.findBySubdomain("superadmin").isEmpty()) {
            Organization superadminOrg = new Organization();
            superadminOrg.setName("Superadmin");
            superadminOrg.setSubdomain("superadmin");
            organizationRepository.save(superadminOrg);
            System.out.println("✅ Created 'superadmin' organization entry.");
        }

        // 2. Find or Create the Superadmin User
        // This logic will find an existing 'admin' or create a new one
        user superAdmin = userRepository.findByUsernameAndOrganizationIdIsNull("admin")
                .orElse(new user()); // Get existing or create new

        // 3. Set/Update all properties to ensure consistency
        // This will fix any NULL values on an existing user
        superAdmin.setUsername("admin");
        superAdmin.setPassword(passwordEncoder.encode("admin123")); // Your password
        superAdmin.setEmail("superadmin@app.com");
        superAdmin.setFirstName("Super");
        superAdmin.setLastName("Admin");
        superAdmin.setRole("ROLE_SUPER_ADMIN");
        superAdmin.setActive(true); // <-- This is the explicit fix for the NULL
        superAdmin.setCreatedVia("SYSTEM");
        superAdmin.setOrganization(null); // Ensure it's not tied to any org

        userRepository.save(superAdmin);
        System.out.println("✅ Superadmin user 'admin' is configured.");
    }
}

