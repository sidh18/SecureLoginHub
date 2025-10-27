//package com.example.loginapp.config;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.stereotype.Component;
//
//import javax.crypto.SecretKey;
//import java.security.KeyFactory;
//import java.security.PublicKey;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
//import java.util.List;
//import java.util.stream.Collectors;
//
//@Component
//public class JwtUtil {
//
//    @Value("${miniorange.jwt.issuer}")
//    private String issuer;
//
//    @Value("${miniorange.jwt.secret:}")
//    private String sharedSecret;
//
//    @Value("${miniorange.jwt.public.key:}")
//    private String publicKeyBase64;
//
//    public Claims parseJwt(String token) {
//        if (sharedSecret != null && !sharedSecret.isEmpty()) {
//            SecretKey key = Keys.hmacShaKeyFor(sharedSecret.getBytes());
//            return Jwts.parser()
//                    .verifyWith(key)
//                    .build()
//                    .parseSignedClaims(token)
//                    .getPayload();
//        } else {
//            try {
//                byte[] publicBytes = Base64.getDecoder().decode(publicKeyBase64);
//                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//                PublicKey publicKey = keyFactory.generatePublic(keySpec);
//                return Jwts.parser()
//                        .verifyWith(publicKey)
//                        .requireIssuer(issuer)
//                        .build()
//                        .parseSignedClaims(token)
//                        .getPayload();
//            } catch (Exception e) {
//                throw new RuntimeException("Failed to load public key or parse JWT", e);
//            }
//        }
//    }
//
//    public String getUsername(Claims claims) {
//        return claims.getSubject();
//    }
//
//    public List<SimpleGrantedAuthority> getAuthorities(Claims claims) {
//        @SuppressWarnings("unchecked")
//        List<String> roles = claims.get("roles", List.class);
//        if (roles == null) roles = List.of("ROLE_USER");
//        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
//    }
//
//    public boolean isValid(Claims claims) {
//        return issuer.equals(claims.getIssuer()) && !claims.getExpiration().before(new java.util.Date());
//    }
//}