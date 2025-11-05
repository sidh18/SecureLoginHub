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
import jakarta.servlet.DispatcherType; // <-- IMPORT THIS

/**
 * This filter is the "receptionist" for our multi-tenant application.
 * It runs *before* all other filters (including security) to identify
 * which tenant is making the request based on the domain.
 *
 * e.g., "acme.localhost:8190" -> sets TenantContext to Organization ID 5
 * e.g., "superadmin.localhost:8190" -> sets TenantContext to null (Superadmin)
 */
@Component
public class TenantIdentifierFilter extends OncePerRequestFilter {

    @Autowired
    private OrganizationRepository organizationRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // --- FIX: Prevent filter from running on internal ERROR dispatches ---
        // This stops the filter from running a second time when sendError() is called,
        // which prevents duplicate queries and the "Cache miss" warning.
        if (request.getDispatcherType().equals(DispatcherType.ERROR)) {
            filterChain.doFilter(request, response);
            return;
        }
        // --- END FIX ---

        // Get the full host from the request header
        // e.g., "acme.localhost:8190"
        String host = request.getHeader("Host");

        try {
            if (host != null) {
                // Split the host to get the subdomain part
                // We split on "." and take the first part.
                String subdomain = host.split("\\.")[0];

                // --- FIX: Treat 'localhost' and 'superadmin' as special non-tenant domains ---
                if ("superadmin".equalsIgnoreCase(subdomain) || "localhost".equalsIgnoreCase(subdomain)) {
                    // We set the context to null to signify "god mode" or "root".
                    TenantContext.setCurrentOrganizationId(null);
                    TenantContext.setCurrentSubdomain(subdomain); // Also store subdomain
                } else {
                    // It's a regular tenant domain. Look it up.
                    Optional<Organization> org = organizationRepository.findBySubdomain(subdomain);

                    if (org.isPresent()) {
                        // Found it! Set the organization ID for this entire request.
                        TenantContext.setCurrentOrganizationId(org.get().getId());
                        TenantContext.setCurrentSubdomain(subdomain); // Also store subdomain
                    } else {
                        // This is a domain we don't recognize.
                        // Send a 404 error and STOP the request chain.
                        // (Removed logger.warn as it was causing issues)
                        response.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown organization: " + subdomain);
                        // We set the context to null just in case, but we don't call filterChain.
                        TenantContext.clear();
                        return; // <-- This is the crucial part, stop the filter chain.
                    }
                }
            } else {
                // No host header. This is unusual but possible.
                // (Removed logger.warn as it was causing issues)
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Host header is missing.");
                TenantContext.clear();
                return; // Stop the chain
            }

            // Continue the request chain
            filterChain.doFilter(request, response);

        } finally {
            // CRITICAL: After the request is complete (even if it fails),
            // we MUST clear the ThreadLocal to prevent data leakage
            // to the next request that uses this thread.
            TenantContext.clear();
        }
    }
}

