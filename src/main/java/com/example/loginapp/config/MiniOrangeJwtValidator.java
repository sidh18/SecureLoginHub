//package com.example.loginapp.config;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Component;
//
//import java.security.KeyFactory;
//import java.security.PublicKey;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
//import java.util.Date;
//
//@Component
//public class MiniOrangeJwtValidator {
//
//    @Value("${miniorange.jwt.issuer}")
//    private String issuer;
//
//    @Value("${miniorange.jwt.public.key}")
//    private String publicKeyPem;
//
//    private PublicKey getPublicKey() throws Exception {
//        String key = publicKeyPem
//                .replace("-----BEGIN PUBLIC KEY-----", "")
//                .replace("-----END PUBLIC KEY-----", "")
//                .replaceAll("\\s", "");
//        byte[] decoded = Base64.getDecoder().decode(key);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
//        return KeyFactory.getInstance("RSA").generatePublic(spec);
//    }
//
//    public String extractUsername(String token) throws Exception {
//        return parseToken(token).getSubject();
//    }
//
//    public boolean validateToken(String token) throws Exception {
//        Claims claims = parseToken(token);
//        return issuer.equals(claims.getIssuer()) && claims.getExpiration().after(new Date());
//    }
//
//    private Claims parseToken(String token) throws Exception {
//        return Jwts.parserBuilder()
//                .setSigningKey(getPublicKey())
//                .requireIssuer(issuer)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    public Claims validateAndParse(String token) throws Exception {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(getPublicKey())
//                .requireIssuer(issuer)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//        if (claims.getExpiration().before(new Date())) {
//            throw new RuntimeException("Token expired");
//        }
//        return claims;
//    }
//}
//
////package com.example.loginapp.config;
////
////import io.jsonwebtoken.Claims;
////import io.jsonwebtoken.Jwts;
////import org.springframework.beans.factory.annotation.Value;
////import org.springframework.stereotype.Component;
////
////import java.security.KeyFactory;
////import java.security.PublicKey;
////import java.security.spec.X509EncodedKeySpec;
////import java.util.Base64;
////import java.util.Date;
////
////@Component
////public class MiniOrangeJwtValidator {
////
////    @Value("${miniorange.jwt.issuer}")
////    private String issuer;
////
////    @Value("${miniorange.jwt.public.key}")
////    private String publicKeyPem;
////
////    private PublicKey getPublicKey() throws Exception {
////        String key = publicKeyPem
////                .replace("-----BEGIN PUBLIC KEY-----", "")
////                .replace("-----END PUBLIC KEY-----", "")
////                .replaceAll("\\s", "");
////        byte[] decoded = Base64.getDecoder().decode(key);
////        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
////        return KeyFactory.getInstance("RSA").generatePublic(spec);
////    }
////
////    public String extractUsername(String token) throws Exception {
////        return parseToken(token).getSubject();
////    }
////
////    public boolean validateToken(String token) throws Exception {
////        Claims claims = parseToken(token);
////        return issuer.equals(claims.getIssuer()) && claims.getExpiration().after(new Date());
////    }
////
////    private Claims parseToken(String token) throws Exception {
////        return Jwts.parserBuilder()
////                .setSigningKey(getPublicKey())
////                .requireIssuer(issuer)
////                .build()
////                .parseClaimsJws(token)
////                .getBody();
////    }
////}
////
//////package com.example.loginapp.config;
//////
//////import io.jsonwebtoken.Claims;
//////import io.jsonwebtoken.Jwts;
//////import org.springframework.beans.factory.annotation.Value;
//////import org.springframework.stereotype.Component;
//////import org.springframework.web.reactive.function.client.WebClient;
//////
//////import java.security.KeyFactory;
//////import java.security.PublicKey;
//////import java.security.spec.X509EncodedKeySpec;
//////import java.util.Base64;
//////import java.util.Map;
//////
//////@Component
//////public class MiniOrangeJwtValidator {
//////
//////    @Value("${miniorange.jwt.public-key-url}")
//////    private String publicKeyUrl;
//////
//////    @Value("${miniorange.jwt.issuer}")
//////    private String expectedIssuer;
//////
//////    @Value("${miniorange.jwt.api-key}")
//////    private String apiKey;
//////
//////    private final WebClient webClient;
//////    private PublicKey cachedPublicKey;
//////
//////    public MiniOrangeJwtValidator() {
//////        this.webClient = WebClient.builder().build();
//////    }
//////
//////    /**
//////     * Validate MiniOrange JWT token
//////     */
//////    public boolean validateMiniOrangeToken(String token) {
//////        try {
//////            PublicKey publicKey = getPublicKey();
//////
//////            Claims claims = Jwts.parserBuilder()
//////                    .setSigningKey(publicKey)
//////                    .build()
//////                    .parseClaimsJws(token)
//////                    .getBody();
//////
//////            // Validate issuer
//////            String issuer = claims.getIssuer();
//////            if (!expectedIssuer.equals(issuer)) {
//////                System.err.println("Invalid issuer: " + issuer);
//////                return false;
//////            }
//////
//////            return true;
//////        } catch (Exception e) {
//////            System.err.println("Token validation failed: " + e.getMessage());
//////            return false;
//////        }
//////    }
//////
//////    /**
//////     * Extract username from MiniOrange JWT token
//////     */
//////    public String extractUsername(String token) {
//////        try {
//////            PublicKey publicKey = getPublicKey();
//////
//////            Claims claims = Jwts.parserBuilder()
//////                    .setSigningKey(publicKey)
//////                    .build()
//////                    .parseClaimsJws(token)
//////                    .getBody();
//////
//////            // MiniOrange typically uses 'sub' or 'email' or 'username'
//////            String username = claims.getSubject();
//////            if (username == null || username.isEmpty()) {
//////                username = (String) claims.get("email");
//////            }
//////            if (username == null || username.isEmpty()) {
//////                username = (String) claims.get("username");
//////            }
//////
//////            return username;
//////        } catch (Exception e) {
//////            System.err.println("Failed to extract username: " + e.getMessage());
//////            return null;
//////        }
//////    }
//////
//////    /**
//////     * Extract all claims from MiniOrange JWT token
//////     */
//////    public Map<String, Object> extractAllClaims(String token) {
//////        try {
//////            PublicKey publicKey = getPublicKey();
//////
//////            Claims claims = Jwts.parserBuilder()
//////                    .setSigningKey(publicKey)
//////                    .build()
//////                    .parseClaimsJws(token)
//////                    .getBody();
//////
//////            return claims;
//////        } catch (Exception e) {
//////            System.err.println("Failed to extract claims: " + e.getMessage());
//////            return null;
//////        }
//////    }
//////
//////    /**
//////     * Fetch public key from MiniOrange
//////     */
//////    private PublicKey getPublicKey() throws Exception {
//////        if (cachedPublicKey != null) {
//////            return cachedPublicKey;
//////        }
//////
//////        // Fetch public key from MiniOrange
//////        Map<String, Object> response = webClient.get()
//////                .uri(publicKeyUrl)
//////                .header("X-API-Key", apiKey)
//////                .retrieve()
//////                .bodyToMono(Map.class)
//////                .block();
//////
//////        if (response == null || !response.containsKey("publicKey")) {
//////            throw new Exception("Failed to fetch public key from MiniOrange");
//////        }
//////
//////        String publicKeyPEM = (String) response.get("publicKey");
//////
//////        // Remove PEM headers and decode
//////        publicKeyPEM = publicKeyPEM
//////                .replace("-----BEGIN PUBLIC KEY-----", "")
//////                .replace("-----END PUBLIC KEY-----", "")
//////                .replaceAll("\\s", "");
//////
//////        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
//////        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
//////        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//////
//////        cachedPublicKey = keyFactory.generatePublic(keySpec);
//////        return cachedPublicKey;
//////    }
//////
//////    /**
//////     * Clear cached public key (useful for key rotation)
//////     */
//////    public void clearCachedKey() {
//////        cachedPublicKey = null;
//////    }
//////}