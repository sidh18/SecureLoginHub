package com.example.loginapp.controller;

import com.example.loginapp.model.user;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.service.AdminService;
import com.example.loginapp.service.SsoConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private AdminService adminService;

    @Autowired
    private SsoConfigService ssoConfigService;

    /**
     * Admin Dashboard Home
     */
    @GetMapping("/dashboard")
    public String adminDashboard(Model model, Authentication authentication) {
        // Check if user is admin
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return "home";
        }

        List<user> users = adminService.getAllUsers();
        List<SsoConfig> ssoConfigs = ssoConfigService.getAllSsoConfigs();

        // FIX: Provide a new, empty SsoConfig object instead of null
        // This prevents the Thymeleaf template from crashing.
        SsoConfig activeSsoConfig = ssoConfigService.getEnabledSsoConfigs()
                .stream()
                .findFirst()
                .orElse(new SsoConfig()); // Changed from orElse(null)

        model.addAttribute("users", users);
        model.addAttribute("ssoConfigs", ssoConfigs);
        model.addAttribute("adminUsername", authentication.getName());
        model.addAttribute("ssoConfig", activeSsoConfig);

        return "admin-dashboard";
    }

    /**
     * Get all users (REST API)
     */
    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<List<user>> getAllUsers(Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).build();
        }

        List<user> users = adminService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Create new user
     */
    @PostMapping("/api/users")
    @ResponseBody
    public ResponseEntity<?> createUser(@RequestBody Map<String, String> request,
                                        Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            String username = request.get("username");
            String password = request.get("password");
            String email = request.get("email");
            String firstName = request.get("firstName");
            String lastName = request.get("lastName");
            String role = request.get("role");

            user user = adminService.createUser(username, password, email, firstName, lastName, role);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Update user
     */
    @PutMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> updateUser(@PathVariable Long id,
                                        @RequestBody Map<String, Object> request,
                                        Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            String username = (String) request.get("username");
            String email = (String) request.get("email");
            String firstName = (String) request.get("firstName");
            String lastName = (String) request.get("lastName");
            String role = (String) request.get("role");
            Boolean active = (Boolean) request.get("active");

            user user = adminService.updateUser(id, username, email, firstName, lastName, role, active);
            if (user == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Delete user
     */
    @DeleteMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteUser(@PathVariable Long id, Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        boolean deleted = adminService.deleteUser(id);
        if (deleted) {
            return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Get all SSO configurations
     */
    @GetMapping("/api/sso-configs")
    @ResponseBody
    public ResponseEntity<List<SsoConfig>> getAllSsoConfigs(Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).build();
        }

        List<SsoConfig> configs = ssoConfigService.getAllSsoConfigs();
        return ResponseEntity.ok(configs);
    }

    /**
     * Get specific SSO configuration
     */
    @GetMapping("/api/sso-configs/{id}")
    @ResponseBody
    public ResponseEntity<SsoConfig> getSsoConfig(@PathVariable Long id, Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).build();
        }

        SsoConfig config = ssoConfigService.getSsoConfigById(id);
        if (config == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(config);
    }

    /**
     * Toggle SSO
     */
    @PostMapping("/api/sso-configs/{id}/toggle")
    @ResponseBody
    public ResponseEntity<?> toggleSso(@PathVariable Long id,
                                       @RequestBody Map<String, Boolean> request,
                                       Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        boolean enabled = request.get("enabled");
        SsoConfig config = ssoConfigService.toggleSso(id, enabled, authentication.getName());
        if (config == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(config);
    }

    /**
     * Save JWT configuration
     */
    @PostMapping("/api/sso-configs/jwt")
    @ResponseBody
    public ResponseEntity<?> saveJwtConfig(@RequestBody Map<String, Object> request,
                                           Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            Long id = request.get("id") != null ? Long.valueOf(request.get("id").toString()) : null;
            String name = (String) request.get("name");
            String clientId = (String) request.get("clientId");
            String ssoUrl = (String) request.get("ssoUrl");
            String callbackUrl = (String) request.get("callbackUrl");
            String logoutUrl = (String) request.get("logoutUrl");
            Integer priority = request.get("priority") != null ? (Integer) request.get("priority") : 0;

            SsoConfig config;
            if (id != null) {
                config = ssoConfigService.updateJwtConfig(id, name, clientId, ssoUrl, callbackUrl,
                        logoutUrl, priority, authentication.getName());
            } else {
                config = ssoConfigService.saveJwtConfig(name, clientId, ssoUrl, callbackUrl,
                        logoutUrl, priority, authentication.getName());
            }

            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Save OAuth configuration
     */
    @PostMapping("/api/sso-configs/oauth")
    @ResponseBody
    public ResponseEntity<?> saveOAuthConfig(@RequestBody Map<String, Object> request,
                                             Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

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

            SsoConfig config;
            if (id != null) {
                config = ssoConfigService.updateOAuthConfig(id, name, clientId, clientSecret,
                        authUrl, tokenUrl, callbackUrl, userInfoUrl,
                        priority, authentication.getName());
            } else {
                config = ssoConfigService.saveOAuthConfig(name, clientId, clientSecret, authUrl,
                        tokenUrl, callbackUrl, userInfoUrl,
                        priority, authentication.getName());
            }

            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Save SAML configuration
     */
    @PostMapping("/api/sso-configs/saml")
    @ResponseBody
    public ResponseEntity<?> saveSamlConfig(@RequestBody Map<String, Object> request,
                                            Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            Long id = request.get("id") != null ? Long.valueOf(request.get("id").toString()) : null;
            String name = (String) request.get("name");
            String entityId = (String) request.get("entityId");
            String idpEntityId = (String) request.get("idpEntityId");
            String ssoUrl = (String) request.get("ssoUrl");
            String certificate = (String) request.get("certificate");
            String acsUrl = (String) request.get("acsUrl");
            Integer priority = request.get("priority") != null ? (Integer) request.get("priority") : 0;

            SsoConfig config;
            if (id != null) {
                config = ssoConfigService.updateSamlConfig(id, name, entityId, idpEntityId,
                        ssoUrl, certificate, acsUrl,
                        priority, authentication.getName());
            } else {
                config = ssoConfigService.saveSamlConfig(name, entityId, idpEntityId, ssoUrl,
                        certificate, acsUrl,
                        priority, authentication.getName());
            }

            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Parse IDP metadata
     */
    @PostMapping("/api/sso-configs/saml/parse-metadata")
    @ResponseBody
    public ResponseEntity<?> parseIdpMetadata(@RequestBody Map<String, String> request,
                                              Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            String metadataXml = request.get("metadata");
            Map<String, String> parsedData = ssoConfigService.parseIdpMetadata(metadataXml);
            return ResponseEntity.ok(parsedData);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to parse metadata: " + e.getMessage()));
        }
    }

    /**
     * Delete SSO configuration
     */
    @DeleteMapping("/api/sso-configs/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteSsoConfig(@PathVariable Long id, Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        boolean deleted = ssoConfigService.deleteSsoConfig(id);
        if (deleted) {
            return ResponseEntity.ok(Map.of("message", "SSO configuration deleted successfully"));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Helper method to check if user has role
     */
    private boolean hasRole(Authentication authentication, String role) {
        return authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + role) ||
                        a.getAuthority().equals(role));
    }
}