package com.example.loginapp.config;

import com.example.loginapp.model.Organization;
import com.example.loginapp.repository.OrganizationRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import jakarta.servlet.DispatcherType;

@Component
public class TenantIdentifierFilter extends OncePerRequestFilter {

    @Autowired
    private OrganizationRepository organizationRepository;

    // --- DEFINE YOUR PRODUCTION DOMAIN ---
    // We will get this from an environment variable, but default to your domain
    // In production, you would set: -Dapp.domain=sidhkocheta.cloud
    private final String PRODUCTION_DOMAIN = System.getProperty("app.domain", "sidhkocheta.cloud");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Prevent filter from running on internal ERROR dispatches
        if (request.getDispatcherType().equals(DispatcherType.ERROR)) {
            filterChain.doFilter(request, response);
            return;
        }

        String host = request.getHeader("Host");
        if (host == null) {
            host = request.getServerName();
        }

        // Remove port number if it exists
        if (host.contains(":")) {
            host = host.split(":")[0];
        }

        String subdomain = null;

        // --- NEW DOMAIN LOGIC ---
        if (host.endsWith("." + PRODUCTION_DOMAIN)) {
            // 1. Production Tenant (e.g., "acme.sidhkocheta.cloud")
            subdomain = host.substring(0, host.indexOf("." + PRODUCTION_DOMAIN));

        } else if (host.endsWith(".localhost")) {
            // 2. Local Tenant (e.g., "acme.localhost")
            subdomain = host.substring(0, host.indexOf(".localhost"));

        } else if (host.equals(PRODUCTION_DOMAIN)) {
            // 3. Production Superadmin (e.g., "sidhkocheta.cloud")
            subdomain = "superadmin";

        } else if (host.equals("localhost") || host.equals("superadmin.localhost")) {
            // 4. Local Superadmin (e.g., "localhost" or "superadmin.localhost")
            subdomain = "superadmin";
        }
        // --- END NEW DOMAIN LOGIC ---

        try {
            if ("superadmin".equals(subdomain)) {
                // This is a Superadmin request (local or production)
                TenantContext.setCurrentOrganizationId(null);
                TenantContext.setCurrentSubdomain("superadmin");

            } else if (subdomain != null) {
                // This is a Tenant request (e.g., "acme")
                Optional<Organization> org = organizationRepository.findBySubdomain(subdomain);

                if (org.isPresent()) {
                    // Found it! Set the organization ID for this entire request.
                    TenantContext.setCurrentOrganizationId(org.get().getId());
                    TenantContext.setCurrentSubdomain(subdomain);
                } else {
                    // This is a domain we don't recognize (e.g., "fake.localhost")
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown organization: " + subdomain);
                    TenantContext.clear();
                    return; // Stop the filter chain.
                }
            } else {
                // This is a completely unknown host (e.g., access by IP address)
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid host: " + host);
                TenantContext.clear();
                return; // Stop the chain
            }

            // Continue the request chain
            filterChain.doFilter(request, response);

        } finally {
            // CRITICAL: Always clear the ThreadLocal
            TenantContext.clear();
        }
    }
}