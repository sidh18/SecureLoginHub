//package com.example.loginapp.config;
//
//import io.jsonwebtoken.Claims;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.util.stream.Collectors;
//
//@Component
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
//
//    private final JwtUtil jwtUtil;
//
//    // Constructor injection
//    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
//        this.jwtUtil = jwtUtil;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//        String token = extractToken(request);
//        if (token != null) {
//            try {
//                Claims claims = jwtUtil.parseJwt(token);
//                if (jwtUtil.isValid(claims)) {
//                    String username = jwtUtil.getUsername(claims);
//                    var authorities = jwtUtil.getAuthorities(claims).stream().collect(Collectors.toList());
//
//                    User principal = new User(username, "", authorities);
//                    UsernamePasswordAuthenticationToken authentication =
//                            new UsernamePasswordAuthenticationToken(principal, null, authorities);
//                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                    SecurityContextHolder.getContext().setAuthentication(authentication);
//                    logger.info("Authenticated user: {}", username);
//                } else {
//                    logger.warn("Invalid JWT token");
//                }
//            } catch (Exception e) {
//                logger.warn("JWT validation failed: {}", e.getMessage());
//            }
//        }
//        filterChain.doFilter(request, response);
//    }
//
//    private String extractToken(HttpServletRequest request) {
//        String token = request.getParameter("token");
//        if (token == null) {
//            String authHeader = request.getHeader("Authorization");
//            if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                token = authHeader.substring(7);
//            }
//        }
//        return token;
//    }
//}