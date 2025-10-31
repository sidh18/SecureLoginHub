package com.example.loginapp.config;

import com.example.loginapp.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    // --- FIX: ---
    // Add all public prefixes to this list
    private static final List<String> PUBLIC_PATHS_PREFIXES = Arrays.asList(
            "/sso/",
            "/saml/",
            "/oauth/"
    );

    // Add all public exact paths
    private static final List<String> PUBLIC_PATHS_EXACT = Arrays.asList(
            "/",
            "/signup",
            "/register",
            "/login",
            "/api/test",
            "/error"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // --- FIX: ---
        // Check if the path is public
        boolean isPublicPrefix = PUBLIC_PATHS_PREFIXES.stream().anyMatch(path::startsWith);
        boolean isPublicExact = PUBLIC_PATHS_EXACT.contains(path);

        // If it's a public path, skip the filter logic
        if (isPublicPrefix || isPublicExact) {
            filterChain.doFilter(request, response);
            return;
        }

        // --- Your existing logic ---
        String authorizationHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        // Extract JWT token from header
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(token);
            } catch (Exception e) {
                logger.error("JWT Token extraction failed", e);
            }
        }

        // Validate token and set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}

