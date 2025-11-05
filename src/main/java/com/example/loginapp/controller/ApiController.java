package com.example.loginapp.controller;

import com.example.loginapp.config.TenantContext;
import com.example.loginapp.model.Organization;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.service.SsoConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private SsoConfigService ssoConfigService;

    @Autowired
    private OrganizationRepository organizationRepository;

    /**
     * A simple public endpoint for testing.
     */
    @GetMapping("/test")
    public ResponseEntity<Map<String, String>> testApi() {
        return ResponseEntity.ok(Map.of("message", "API is working!"));
    }

    /**
     * Endpoint to get public information about the current tenant
     * This is called by the login.html page.
     */
    @GetMapping("/tenant/info")
    public ResponseEntity<Map<String, String>> getTenantInfo() {
        Long organizationId = TenantContext.getCurrentOrganizationId();

        if (organizationId == null) {
            // This could be the superadmin.localhost domain or a non-tenant domain
            // Check the subdomain
            String subdomain = TenantContext.getCurrentSubdomain();
            if ("superadmin".equals(subdomain)) {
                return ResponseEntity.ok(Map.of("name", "Superadmin Login"));
            }
            // You can decide what to show for the 'root' domain
            return ResponseEntity.ok(Map.of("name", "Login"));
        }

        Optional<Organization> org = organizationRepository.findById(organizationId);
        if (org.isPresent()) {
            return ResponseEntity.ok(Map.of("name", org.get().getName()));
        } else {
            // This case should ideally not happen if TenantIdentifierFilter is working
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Endpoint to get the list of ENABLED SSO configurations
     * for the current tenant. This is called by the login.html page.
     */
    @GetMapping("/sso-configs/tenant")
    public ResponseEntity<List<SsoConfig>> getTenantSsoConfigs() {
        Long organizationId = TenantContext.getCurrentOrganizationId();

        if (organizationId == null) {
            // Superadmin domain has no SSO login, only username/password
            return ResponseEntity.ok(Collections.emptyList());
        }

        List<SsoConfig> configs = ssoConfigService.getEnabledSsoConfigsForOrganization(organizationId);
        return ResponseEntity.ok(configs);
    }
}

