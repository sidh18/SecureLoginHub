package com.example.loginapp.controller;

import com.example.loginapp.config.JwtUtil; // <-- IMPORT
import com.example.loginapp.model.Organization;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.model.user;
import com.example.loginapp.security.CustomUserDetails;
import com.example.loginapp.service.AdminService;
import com.example.loginapp.service.SsoConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller for Superadmin functions.
 * All endpoints are secured by SecurityConfig to ROLE_SUPER_ADMIN.
 */
@Controller
@RequestMapping("/superadmin")
public class SuperadminController {

    @Autowired
    private AdminService adminService;

    @Autowired
    private SsoConfigService ssoConfigService;

    @Autowired
    private JwtUtil jwtUtil; // <-- INJECT JWTUTIL

    /**
     * Helper method to get the current authenticated user's details.
     */
    private CustomUserDetails getAuthUser(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            throw new SecurityException("User is not authenticated or session is invalid.");
        }
        return (CustomUserDetails) authentication.getPrincipal();
    }

    /**
     * Superadmin Dashboard Home
     */
    @GetMapping("/dashboard")
    public String superadminDashboard(Model model, Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);

        // --- FIX: GENERATE A JWT FOR THE API ---
        String jwtToken = jwtUtil.generateToken(authUser);
        model.addAttribute("jwtToken", jwtToken);
        // --- END FIX ---

        model.addAttribute("adminUsername", authUser.getUsername());
        return "superadmin-dashboard";
    }

    // --- Superadmin API Endpoints ---
    // (All other methods remain exactly the same)
    // ...

    /**
     * Get global statistics for the superadmin dashboard.
     */
    @GetMapping("/api/stats")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getGlobalStats() {
        Map<String, Object> stats = adminService.getGlobalStats();
        return ResponseEntity.ok(stats);
    }

    /**
     * Get all organizations.
     */
    @GetMapping("/api/organizations")
    @ResponseBody
    public ResponseEntity<List<Organization>> getAllOrganizations() {
        return ResponseEntity.ok(adminService.getAllOrganizations());
    }

    /**
     * Create a new organization.
     * This ONLY creates the organization, not the admin.
     */
    @PostMapping("/api/organizations")
    @ResponseBody
    public ResponseEntity<?> createOrganization(@RequestBody Map<String, String> request) {
        try {
            String orgName = request.get("name");
            String subdomain = request.get("subdomain");

            if (orgName == null || subdomain == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Name and Subdomain are required."));
            }
            Organization org = adminService.createOrganization(orgName, subdomain);
            return ResponseEntity.ok(org);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Create a new Tenant Admin for an existing organization.
     */
    @PostMapping("/api/users/create-admin")
    @ResponseBody
    public ResponseEntity<?> createTenantAdmin(@RequestBody Map<String, Object> request) {
        try {
            String username = (String) request.get("username");
            String password = (String) request.get("password");
            String email = (String) request.get("email");
            String firstName = (String) request.get("firstName");
            String lastName = (String) request.get("lastName");
            Long organizationId = Long.valueOf(request.get("organizationId").toString());

            if (username == null || password == null || organizationId == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Username, Password, and OrganizationID are required."));
            }

            // Call createUser with ROLE_ADMIN
            user admin = adminService.createUser(username, password, email, firstName, lastName, "ROLE_ADMIN", organizationId);
            return ResponseEntity.ok(admin);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Get all users (global) with optional filtering by organization.
     */
    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<List<user>> getAllUsers(@RequestParam(required = false) Long orgId) {
        List<user> users;
        if (orgId != null) {
            // Get users for a specific org
            users = adminService.getAllUsersForOrganization(orgId);
        } else {
            // Get all users
            users = adminService.getAllUsersForSuperAdmin();
        }
        return ResponseEntity.ok(users);
    }

    /**
     * Get a single user by ID (Superadmin has global access).
     */
    @GetMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        try {
            // Pass 'null' for orgId to signify superadmin access
            user user = adminService.getUserById(id, null);
            if (user == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(user);
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Create a new user globally (Superadmin).
     */
    @PostMapping("/api/users")
    @ResponseBody
    public ResponseEntity<?> createUser(@RequestBody Map<String, Object> request) {
        try {
            String username = (String) request.get("username");
            String password = (String) request.get("password");
            String email = (String) request.get("email");
            String firstName = (String) request.get("firstName");
            String lastName = (String) request.get("lastName");
            String role = (String) request.get("role");
            Long orgIdToAssign = request.get("organizationId") != null ? Long.valueOf(request.get("organizationId").toString()) : null;

            if (username == null || password == null || role == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Username, Password and Role are required."));
            }

            // Superadmin can create any role
            if ("ROLE_SUPER_ADMIN".equals(role)) {
                orgIdToAssign = null; // Superadmins have null orgId
            } else if (orgIdToAssign == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "OrganizationID is required for Users and Tenant Admins."));
            }

            user user = adminService.createUser(username, password, email, firstName, lastName, role, orgIdToAssign);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Update any user (Superadmin).
     */
    @PutMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> updateUser(@PathVariable Long id,
                                        @RequestBody Map<String, Object> request) {
        try {
            String username = (String) request.get("username");
            String email = (String) request.get("email");
            String firstName = (String) request.get("firstName");
            String lastName = (String) request.get("lastName");
            String role = (String) request.get("role");
            Boolean active = (Boolean) request.get("active");
            Long orgIdToAssign = request.get("organizationId") != null ? Long.valueOf(request.get("organizationId").toString()) : null;

            if ("ROLE_SUPER_ADMIN".equals(role)) {
                orgIdToAssign = null; // Superadmins have null orgId
            }

            // Pass 'null' for adminOrgId to signify superadmin access
            // Pass 'true' for isSuperAdmin flag
            user user = adminService.updateUser(id, username, email, firstName, lastName, role, active, null, true);

            // Special case: Superadmin can also change a user's organization
            if (user != null && orgIdToAssign != null &&
                    (user.getOrganization() == null || !orgIdToAssign.equals(user.getOrganization().getId()))) {
                adminService.changeUserOrganization(id, orgIdToAssign);
                user = adminService.getUserById(id, null); // Re-fetch user
            }

            if (user == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Delete any user (Superadmin).
     */
    @DeleteMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            // Pass 'null' for adminOrgId and 'true' for isSuperAdmin
            boolean deleted = adminService.deleteUser(id, null, true);
            if (deleted) {
                return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Get all SSO configs (global, read-only list).
     */
    @GetMapping("/api/sso-configs")
    @ResponseBody
    public ResponseEntity<List<SsoConfig>> getAllSsoConfigs() {
        List<SsoConfig> configs = ssoConfigService.getAllSsoConfigsForSuperAdmin();
        return ResponseEntity.ok(configs);
    }
}

