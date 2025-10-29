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
        SsoConfig ssoConfig = ssoConfigService.getSsoConfig();

        model.addAttribute("users", users);
        model.addAttribute("ssoConfig", ssoConfig);
        model.addAttribute("adminUsername", authentication.getName());

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
     * Get SSO configuration
     */
    @GetMapping("/api/sso-config")
    @ResponseBody
    public ResponseEntity<SsoConfig> getSsoConfig(Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).build();
        }

        SsoConfig config = ssoConfigService.getSsoConfig();
        return ResponseEntity.ok(config);
    }

    /**
     * Toggle SSO
     */
    @PostMapping("/api/sso-config/toggle")
    @ResponseBody
    public ResponseEntity<?> toggleSso(@RequestBody Map<String, Boolean> request,
                                       Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        boolean enabled = request.get("enabled");
        SsoConfig config = ssoConfigService.toggleSso(enabled, authentication.getName());
        return ResponseEntity.ok(config);
    }

    /**
     * Save JWT configuration
     */
    @PostMapping("/api/sso-config/jwt")
    @ResponseBody
    public ResponseEntity<?> saveJwtConfig(@RequestBody Map<String, String> request,
                                           Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            String clientId = request.get("clientId");
            String ssoUrl = request.get("ssoUrl");
            String callbackUrl = request.get("callbackUrl");
            String logoutUrl = request.get("logoutUrl");

            SsoConfig config = ssoConfigService.saveJwtConfig(clientId, ssoUrl, callbackUrl,
                    logoutUrl, authentication.getName());
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Save OAuth configuration
     */
    @PostMapping("/api/sso-config/oauth")
    @ResponseBody
    public ResponseEntity<?> saveOAuthConfig(@RequestBody Map<String, String> request,
                                             Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            String clientId = request.get("clientId");
            String clientSecret = request.get("clientSecret");
            String authUrl = request.get("authorizationUrl");
            String tokenUrl = request.get("tokenUrl");
            String callbackUrl = request.get("callbackUrl");

            SsoConfig config = ssoConfigService.saveOAuthConfig(clientId, clientSecret, authUrl,
                    tokenUrl, callbackUrl,
                    authentication.getName());
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Save SAML configuration
     */
    @PostMapping("/api/sso-config/saml")
    @ResponseBody
    public ResponseEntity<?> saveSamlConfig(@RequestBody Map<String, String> request,
                                            Authentication authentication) {
        if (authentication == null || !hasRole(authentication, "ADMIN")) {
            return ResponseEntity.status(403).body(Map.of("error", "Unauthorized"));
        }

        try {
            String entityId = request.get("entityId");
            String ssoUrl = request.get("ssoUrl");
            String certificate = request.get("certificate");
            String callbackUrl = request.get("callbackUrl");

            SsoConfig config = ssoConfigService.saveSamlConfig(entityId, ssoUrl, certificate,
                    callbackUrl, authentication.getName());
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
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