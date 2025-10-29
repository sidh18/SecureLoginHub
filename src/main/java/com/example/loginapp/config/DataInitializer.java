package com.example.loginapp.config;

import com.example.loginapp.model.user;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Create default admin user if it doesn't exist
        if (userRepository.findByUsername("admin") == null) {
            user admin = new user();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123"));
//            admin.setEmail("admin@example.com");
//            admin.setFirstName("Admin");
//            admin.setLastName("User");
            admin.setRole("ADMIN");
            admin.setActive(true);
            admin.setCreatedAt(LocalDateTime.now());
            admin.setCreatedVia("SYSTEM");

            userRepository.save(admin);

            System.out.println("========================================");
            System.out.println("✅ Default admin user created!");
            System.out.println("   Username: admin");
            System.out.println("   Password: admin123");
            System.out.println("========================================");
        }
    }
}