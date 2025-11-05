package com.example.loginapp.config;

import com.example.loginapp.security.CustomUserDetails;
import com.example.loginapp.service.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@Order(2) // Runs after TenantIdentifierFilter @Order(1)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    // A list of public paths to skip
    private static final List<String> PUBLIC_PATHS = List.of(
            "/",
            "/signup",
            "/register",
            "/api/test",
            "/login", // <-- Skipping /login is important for form auth
            "/logout",
            "/error",
            "/api/tenant/info", // <-- API for login page
            "/api/sso-configs/tenant" // <-- API for login page
    );

    // A list of public path prefixes to skip
    private static final List<String> PUBLIC_PATH_PREFIXES = List.of(
            "/sso/",
            "/saml/",
            "/oauth/"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // Check if the path is in our public lists
        boolean isPublicPath = PUBLIC_PATHS.contains(path) ||
                PUBLIC_PATH_PREFIXES.stream().anyMatch(path::startsWith);

        // If it's a public path (like /login), skip all JWT logic
        // and let the filter chain continue (to the TenantIdentifierFilter's "finally" block)
        if (isPublicPath) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtUtil.validateToken(jwt)) {
                String username = jwtUtil.extractUsername(jwt);
                Long organizationId = jwtUtil.extractOrganizationId(jwt);
                List<GrantedAuthority> authorities = jwtUtil.extractAuthorities(jwt);

                // --- IMPORTANT ---
                // Manually set the TenantContext for this JWT-authenticated request
                // This ensures all downstream services know the tenant
                // This is safe because TenantIdentifierFilter *already* ran and its
                // context will be cleared by its *own* finally block.
                TenantContext.setCurrentOrganizationId(organizationId);

                // We must use the 4-argument constructor
                CustomUserDetails userDetails = new CustomUserDetails(
                        username,
                        null, // Password is not needed
                        authorities,
                        organizationId
                );

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        // --- FIX: REMOVED THE ENTIRE 'finally' BLOCK ---
        // The TenantIdentifierFilter is already responsible for
        // clearing the TenantCo    ntext in its own 'finally' block,
        // which wraps this entire request.
        // Adding another 'finally' here clears the context prematurely
        // during form login.

        filterChain.doFilter(request, response);
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
