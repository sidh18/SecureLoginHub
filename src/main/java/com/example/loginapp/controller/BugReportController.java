package com.example.loginapp.controller;

import com.example.loginapp.model.BugReport;
import com.example.loginapp.model.Organization;
import com.example.loginapp.model.user;
import com.example.loginapp.repository.BugReportRepository;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.repository.UserRepository;
import com.example.loginapp.security.CustomUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/bugs") // This controller is still mapped to /api/bugs
public class BugReportController {

    @Autowired
    private BugReportRepository bugReportRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    /**
     * Endpoint for ROLE_USER and ROLE_ADMIN to submit a new bug report.
     * This is the only method left in this controller.
     */
    @PostMapping
    public ResponseEntity<?> submitBugReport(@RequestBody Map<String, String> request, Authentication authentication) {
        String description = request.get("description");
        if (description == null || description.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Bug description cannot be empty."));
        }

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        // --- THIS IS THE FIX FOR THE getUserId() ERROR ---
        String username = userDetails.getUsername();
        Long organizationId = userDetails.getOrganizationId(); // Assuming this method exists
        // --- END FIX ---

        if (organizationId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Superadmins cannot submit bug reports."));
        }

        // We must fetch the managed entities
        Optional<user> userOptional = userRepository.findByUsernameAndOrganizationId(username, organizationId);
        Optional<Organization> orgOptional = organizationRepository.findById(organizationId);

        if (userOptional.isEmpty() || orgOptional.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("error", "User or Organization not found."));
        }

        BugReport bugReport = new BugReport();
        bugReport.setDescription(description);
        bugReport.setReportedBy(userOptional.get());
        bugReport.setOrganization(orgOptional.get());

        BugReport savedBug = bugReportRepository.save(bugReport);
        return ResponseEntity.ok(savedBug);
    }
}