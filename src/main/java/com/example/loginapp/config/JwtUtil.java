package com.example.loginapp.config;

import com.example.loginapp.security.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtUtil {

    // You should set this in your application.properties
    @Value("${jwt.secret.key}")
    private String SECRET_KEY;

    @Value("${jwt.expiration.ms}")
    private long jwtExpirationMs;

    // --- 1. GENERATE TOKEN ---
    // This method is called by your AuthController during login

    public String generateToken(CustomUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        // --- NEW MULTI-TENANT CLAIMS ---
        // Add the organization ID
        claims.put("orgId", userDetails.getOrganizationId());

        // Add the user's roles
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claims.put("roles", roles);
        // --- END NEW CLAIMS ---

        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // --- 2. VALIDATE TOKEN ---
    // Used by the JwtAuthenticationFilter

    public Boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // --- 3. EXTRACT INFO FROM TOKEN ---
    // These are the helper methods for the filter and token generation

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * --- NEW METHOD ---
     * Extracts the Organization ID from the "orgId" claim in the token.
     */
    public Long extractOrganizationId(String token) {
        try {
            Object orgId = extractAllClaims(token).get("orgId");
            if (orgId == null) {
                return null; // Superadmin
            }
            // The claim might be stored as an Integer, so we handle it
            return ((Number) orgId).longValue();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * --- NEW METHOD ---
     * Extracts the list of roles from the "roles" claim in the token.
     */
    @SuppressWarnings("unchecked")
    public List<GrantedAuthority> extractAuthorities(String token) {
        try {
            List<String> roles = extractClaim(token, claims -> claims.get("roles", List.class));
            if (roles == null) {
                return List.of(); // No roles found
            }
            return roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            return List.of();
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

