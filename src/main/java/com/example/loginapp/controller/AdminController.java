package com.example.loginapp.controller;

import com.example.loginapp.model.user;
// import com.example.loginapp.model.Organization; // No longer needed here
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.security.CustomUserDetails; // Import our new class
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

@Controller
@RequestMapping("/admin") // This controller is now ONLY for ROLE_ADMIN
public class AdminController {

    @Autowired
    private AdminService adminService;

    @Autowired
    private SsoConfigService ssoConfigService;

    /**
     * Helper method to get the current authenticated user's details.
     */
    private CustomUserDetails getAuthUser(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            // This should not happen if the endpoint is secured, but as a safeguard:
            throw new SecurityException("User is not authenticated or session is invalid.");
        }
        return (CustomUserDetails) authentication.getPrincipal();
    }

    /**
     * Admin Dashboard Home
     * This is now tenant-aware.
     */
    @GetMapping("/dashboard")
    public String adminDashboard(Model model, Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long orgId = authUser.getOrganizationId();

        // --- MODIFIED: Removed all superadmin logic ---
        // A ROLE_ADMIN will always have an orgId
        if (orgId == null) {
            // This should not happen due to SecurityConfig, but as a safeguard
            return "redirect:/logout?error=invalid_session";
        }

        // --- TENANT ADMIN VIEW ---
        List<user> users = adminService.getAllUsersForOrganization(orgId);
        List<SsoConfig> ssoConfigs = ssoConfigService.getAllSsoConfigsForOrganization(orgId);

        model.addAttribute("users", users);
        model.addAttribute("ssoConfigs", ssoConfigs);
        model.addAttribute("adminUsername", authUser.getUsername());
        // model.addAttribute("isSuperAdmin", authUser.isSuperAdmin()); // No longer needed

        // This logic is now handled in the table, so we pass the full list.
        // We find the first *enabled* config for this org, if any.
        SsoConfig activeConfig = ssoConfigs.stream()
                .filter(SsoConfig::getEnabled)
                .findFirst()
                .orElse(null);

        model.addAttribute("activeSsoConfig", activeConfig);

        return "admin-dashboard";
    }

    /**
     * Get all users (Tenant-Aware)
     */
    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<List<user>> getAllUsers(Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long orgId = authUser.getOrganizationId();

        // --- MODIFIED: Removed all superadmin logic ---
        List<user> users = adminService.getAllUsersForOrganization(orgId);
        return ResponseEntity.ok(users);
    }

    /**
     * Get a single user (Tenant-Aware)
     * NEW: Added this endpoint for the "Edit User" modal
     */
    @GetMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> getUser(@PathVariable Long id, Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long adminOrgId = authUser.getOrganizationId();

        try {
            user user = adminService.getUserById(id, adminOrgId);
            if (user == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(user);
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Create new user (Tenant-Aware)
     */
    @PostMapping("/api/users")
    @ResponseBody
    public ResponseEntity<?> createUser(@RequestBody Map<String, String> request,
                                        Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        // A tenant admin can ONLY create users for their own organization.
        Long orgIdToAssign = authUser.getOrganizationId();

        try {
            String username = request.get("username");
            String password = request.get("password");
            String email = request.get("email");
            String firstName = request.get("firstName");
            String lastName = request.get("lastName");
            String role = request.get("role");

            // --- MODIFIED: Security check ---
            // Tenant Admins cannot create Superadmins
            if ("ROLE_SUPER_ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(Map.of("error", "Permission denied."));
            }
            // Tenant Admins can only create ROLE_USER or ROLE_ADMIN
            if (!"ROLE_USER".equals(role) && !"ROLE_ADMIN".equals(role)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid role specified."));
            }

            user user = adminService.createUser(username, password, email, firstName, lastName, role, orgIdToAssign);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Update user (Tenant-Aware)
     */
    @PutMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> updateUser(@PathVariable Long id,
                                        @RequestBody Map<String, Object> request,
                                        Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long adminOrgId = authUser.getOrganizationId(); // Admin's org

        try {
            String username = (String) request.get("username");
            String email = (String) request.get("email");
            String firstName = (String) request.get("firstName");
            String lastName = (String) request.get("lastName");
            String role = (String) request.get("role");
            Boolean active = (Boolean) request.get("active");

            // --- MODIFIED: Security check ---
            // Tenant Admins cannot promote users to Superadmin
            if ("ROLE_SUPER_ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(Map.of("error", "Permission denied."));
            }
            // Tenant Admins can only assign ROLE_USER or ROLE_ADMIN
            if (!"ROLE_USER".equals(role) && !"ROLE_ADMIN".equals(role)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid role specified."));
            }

            // adminService.updateUser will perform the security check
            user user = adminService.updateUser(id, username, email, firstName, lastName, role, active, adminOrgId, false); // false = not superadmin
            if (user == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Delete user (Tenant-Aware)
     */
    @DeleteMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteUser(@PathVariable Long id, Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long adminOrgId = authUser.getOrganizationId(); // Admin's org

        try {
            // adminService.deleteUser will perform the security check
            boolean deleted = adminService.deleteUser(id, adminOrgId, false); // false = not superadmin
            if (deleted) {
                return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // --- DELETED: All endpoints for /api/organizations are moved to SuperadminController ---

    // --- SSO Config Endpoints (Now Tenant-Aware) ---

    @GetMapping("/api/sso-configs")
    @ResponseBody
    public ResponseEntity<List<SsoConfig>> getAllSsoConfigs(Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        // --- MODIFIED: Removed all superadmin logic ---
        List<SsoConfig> configs = ssoConfigService.getAllSsoConfigsForOrganization(authUser.getOrganizationId());
        return ResponseEntity.ok(configs);
    }

    @GetMapping("/api/sso-configs/{id}")
    @ResponseBody
    public ResponseEntity<?> getSsoConfig(@PathVariable Long id, Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        try {
            // Service method already performs tenant security check
            SsoConfig config = ssoConfigService.getSsoConfigById(id, authUser.getOrganizationId());
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/sso-configs/{id}/toggle")
    @ResponseBody
    public ResponseEntity<?> toggleSso(@PathVariable Long id,
                                       @RequestBody Map<String, Boolean> request,
                                       Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        boolean enabled = request.get("enabled");

        try {
            // Service method already performs tenant security check
            SsoConfig config = ssoConfigService.toggleSso(id, enabled, authUser.getUsername(), authUser.getOrganizationId());
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/sso-configs/jwt")
    @ResponseBody
    public ResponseEntity<?> saveJwtConfig(@RequestBody Map<String, Object> request,
                                           Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long adminOrgId = authUser.getOrganizationId();

        try {
            Long id = request.get("id") != null ? Long.valueOf(request.get("id").toString()) : null;
            String name = (String) request.get("name");
            String clientId = (String) request.get("clientId");
            String ssoUrl = (String) request.get("ssoUrl");
            String callbackUrl = (String) request.get("callbackUrl");
            String logoutUrl = (String) request.get("logoutUrl");
            Integer priority = request.get("priority") != null ? (Integer) request.get("priority") : 0;

            // --- MODIFIED: Removed superadmin logic ---
            // Tenant admin can only create for their own org

            SsoConfig config;
            if (id != null) {
                config = ssoConfigService.updateJwtConfig(id, name, clientId, ssoUrl, callbackUrl,
                        logoutUrl, priority, authUser.getUsername(), adminOrgId);
            } else {
                config = ssoConfigService.saveJwtConfig(name, clientId, ssoUrl, callbackUrl,
                        logoutUrl, priority, authUser.getUsername(), adminOrgId);
            }

            return ResponseEntity.ok(config);
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/sso-configs/oauth")
    @ResponseBody
    public ResponseEntity<?> saveOAuthConfig(@RequestBody Map<String, Object> request,
                                             Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long adminOrgId = authUser.getOrganizationId();

        try {
            Long id = request.get("id") != null ? Long.valueOf(request.get("id").toString()) : null;
            String name = (String) request.get("name");
            String clientId = (String) request.get("clientId");
            String clientSecret = (String) request.get("clientSecret");
            String authUrl = (String) request.get("authorizationUrl");
            String tokenUrl = (String) request.get("tokenUrl");
            String callbackUrl = (String) request.get("callbackUrl");
            String userInfoUrl = (String) request.get("userInfoUrl");
            Integer priority = request.get("priority") != null ? (Integer) request.get("priority") : 0;

            // --- MODIFIED: Removed superadmin logic ---
            // Tenant admin can only create for their own org

            SsoConfig config;
            if (id != null) {
                config = ssoConfigService.updateOAuthConfig(id, name, clientId, clientSecret,
                        authUrl, tokenUrl, callbackUrl, userInfoUrl,
                        priority, authUser.getUsername(), adminOrgId);
            } else {
                config = ssoConfigService.saveOAuthConfig(name, clientId, clientSecret, authUrl,
                        tokenUrl, callbackUrl, userInfoUrl,
                        priority, authUser.getUsername(), adminOrgId);
            }

            return ResponseEntity.ok(config);
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/sso-configs/saml")
    @ResponseBody
    public ResponseEntity<?> saveSamlConfig(@RequestBody Map<String, Object> request,
                                            Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        Long adminOrgId = authUser.getOrganizationId();

        try {
            Long id = request.get("id") != null ? Long.valueOf(request.get("id").toString()) : null;
            String name = (String) request.get("name");
            String entityId = (String) request.get("entityId");
            String idpEntityId = (String) request.get("idpEntityId");
            String ssoUrl = (String) request.get("ssoUrl");
            String certificate = (String) request.get("certificate");
            String acsUrl = (String) request.get("acsUrl");
            Integer priority = request.get("priority") != null ? (Integer) request.get("priority") : 0;

            // --- MODIFIED: Removed superadmin logic ---
            // Tenant admin can only create for their own org

            SsoConfig config;
            if (id != null) {
                config = ssoConfigService.updateSamlConfig(id, name, entityId, idpEntityId,
                        ssoUrl, certificate, acsUrl,
                        priority, authUser.getUsername(), adminOrgId);
            } else {
                config = ssoConfigService.saveSamlConfig(name, entityId, idpEntityId, ssoUrl,
                        certificate, acsUrl,
                        priority, authUser.getUsername(), adminOrgId);
            }

            return ResponseEntity.ok(config);
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/sso-configs/saml/parse-metadata")
    @ResponseBody
    public ResponseEntity<?> parseIdpMetadata(@RequestBody Map<String, String> request,
                                              Authentication authentication) {
        // This is a helper, no tenant logic needed
        try {
            String metadataXml = request.get("metadata");
            Map<String, String> parsedData = ssoConfigService.parseIdpMetadata(metadataXml);
            return ResponseEntity.ok(parsedData);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to parse metadata: " + e.getMessage()));
        }
    }

    @DeleteMapping("/api/sso-configs/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteSsoConfig(@PathVariable Long id, Authentication authentication) {
        CustomUserDetails authUser = getAuthUser(authentication);
        try {
            // Service method already performs tenant security check
            boolean deleted = ssoConfigService.deleteSsoConfig(id, authUser.getOrganizationId());
            if (deleted) {
                return ResponseEntity.ok(Map.of("message", "SSO configuration deleted successfully"));
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            // --- FIX: Added missing return statement ---
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}

