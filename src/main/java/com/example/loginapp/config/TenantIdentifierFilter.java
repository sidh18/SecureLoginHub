package com.example.loginapp.config;

import com.example.loginapp.model.Organization;
import com.example.loginapp.repository.OrganizationRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@Order(1) // This filter MUST run first
public class TenantIdentifierFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TenantIdentifierFilter.class);

    @Autowired
    private OrganizationRepository organizationRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String host = request.getHeader("Host"); // e.g., "acme.localhost:8190"
        if (host == null) {
            host = request.getServerName();
        }

        // Remove port number if it exists
        if (host.contains(":")) {
            host = host.split(":")[0];
        }

        String subdomain = null;
        if (host.endsWith(".localhost")) {
            subdomain = host.substring(0, host.indexOf(".localhost"));
        } else if (host.equals("localhost")) {
            subdomain = "localhost";
        } else {
            // Logic for production domains (e.g., myapp.com) would go here
            // For now, we assume .localhost or localhost
            subdomain = "localhost"; // Default to localhost
        }

        try {
            // --- THIS IS THE UPDATED LOGIC ---
            // Treat "localhost" and "superadmin" as the same Superadmin tenant
            if (subdomain.equals("localhost") || subdomain.equals("superadmin")) {

                TenantContext.setCurrentSubdomain("superadmin");
                TenantContext.setCurrentOrganizationId(null);
                log.debug("Setting tenant context for SUPERADMIN (Host: {})", host);

            } else {
                // This is a tenant (e.g., "acme.localhost")
                Optional<Organization> org = organizationRepository.findBySubdomain(subdomain);
                if (org.isPresent()) {
                    TenantContext.setCurrentSubdomain(subdomain);
                    TenantContext.setCurrentOrganizationId(org.get().getId());
                    log.debug("Setting tenant context for Org ID: {} (Host: {})", org.get().getId(), host);
                } else {
                    log.warn("No organization found for subdomain: {}", subdomain);
                    // You could redirect to an error page or the main login
                    // For now, we'll treat it as a non-tenant request
                    TenantContext.setCurrentSubdomain("root-error");
                    TenantContext.setCurrentOrganizationId(null);
                }
            }

            filterChain.doFilter(request, response);

        } finally {
            // VERY IMPORTANT: Clear the context after the request is finished
            TenantContext.clear();
        }
    }
}