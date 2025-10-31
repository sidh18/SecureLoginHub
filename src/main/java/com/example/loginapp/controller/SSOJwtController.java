package com.example.loginapp.controller;

import com.example.loginapp.service.MiniOrangeSsoService;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.service.SsoConfigService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
@RequestMapping("/sso")
public class SSOJwtController {

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    @Autowired
    private SsoConfigService ssoConfigService;

    /**
     * Initiate SSO Login - Redirect to MiniOrange (with config ID)
     */
    @GetMapping("/login/{configId}")
    public void initiateSSO(@PathVariable Long configId, HttpServletResponse response) throws IOException {
        SsoConfig config = ssoConfigService.getSsoConfigById(configId);

        if (config == null || !config.getEnabled() || !"JWT".equals(config.getSsoType())) {
            System.err.println("❌ JWT SSO not configured properly for config ID: " + configId);
            response.sendRedirect("/?error=sso_not_configured");
            return;
        }

        String ssoUrl = config.getJwtSsoUrl();

        if (ssoUrl == null || ssoUrl.isEmpty()) {
            System.err.println("❌ SSO is not configured properly (missing URL)");
            response.sendRedirect("/?error=sso_not_configured");
            return;
        }

        // We pass a 'RelayState' just in case, but our callback
        // logic will primarily rely on the token's 'iss' claim.
        String stateData = "config_id=" + configId;
        String encodedRelayState = URLEncoder.encode(stateData, StandardCharsets.UTF_8);

        String separator = ssoUrl.contains("?") ? "&" : "?";
        String redirectUrl = ssoUrl + separator + "RelayState=" + encodedRelayState;

        System.out.println("\n🔐 ========== SSO LOGIN INITIATED ==========");
        System.out.println("🔗 Config ID: " + configId);
        System.out.println("🔗 Config Name: " + config.getName());
        System.out.println("🔗 Redirecting to MiniOrange SSO: " + redirectUrl);
        System.out.println("==========================================\n");
        response.sendRedirect(redirectUrl);
    }

    /**
     * SSO Callback - Handle response from MiniOrange
     */
    @RequestMapping(value = "/callback", method = {RequestMethod.GET, RequestMethod.POST})
    public String handleCallback(
            HttpServletRequest request,
            // We no longer primarily rely on RelayState
            @RequestParam(required = false) String RelayState,
            HttpSession session,
            Model model) {

        System.out.println("\n🎯 ========== SSO CALLBACK RECEIVED ==========");

        Map<String, String> allParams = new HashMap<>();
        Enumeration<String> paramNames = request.getParameterNames();
        System.out.println("\n📦 All parameters received:");
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String paramValue = request.getParameter(paramName);
            allParams.put(paramName, paramValue);
            if (paramName.equals("id_token") || paramName.equals("token") || paramName.equals("jwt")) {
                System.out.println("   ✓ " + paramName + " = [JWT TOKEN PRESENT - Length: " + paramValue.length() + "]");
            } else {
                System.out.println("   ✓ " + paramName + " = " + paramValue);
            }
        }

        // Try to extract JWT token
        String jwtToken = extractParameter(request, "id_token", "token", "jwt", "access_token");

        if (jwtToken == null || jwtToken.isEmpty()) {
            System.err.println("❌ No JWT token (id_token, token, jwt) found in callback parameters");
            model.addAttribute("error", "SSO Authentication failed: No token received from provider");
            model.addAttribute("allParams", allParams);
            return "sso-error";
        }

        System.out.println("\n🔑 JWT token received, decoding to find issuer (Client ID)...");

        SsoConfig config = null;
        Map<String, Object> jwtClaims = null;
        String username = null;
        String email = null;
        String firstName = null;
        String lastName = null;

        try {
            // --- NEW FIX: ---
            // 1. Decode the JWT to get claims *before* finding the config
            jwtClaims = decodeJWT(jwtToken);
            System.out.println("\n📋 Decoded JWT Claims:");
            for (Map.Entry<String, Object> entry : jwtClaims.entrySet()) {
                System.out.println("   ✓ " + entry.getKey() + " = " + entry.getValue());
            }

            // 2. Get the 'iss' (Issuer) claim from the token.
            // We assume this matches the 'Client ID' in our config.
            String issuer = getClaimValue(jwtClaims, "iss");
            if (issuer == null || issuer.isEmpty()) {
                System.err.println("❌ JWT is missing 'iss' (Issuer) claim.");
                throw new Exception("Failed to process JWT token: JWT is missing 'iss' (Issuer) claim.");
            }

            System.out.println("   ℹ️ Token Issuer (iss): " + issuer);

            // 3. Find the enabled JWT config that matches this Issuer/Client ID
            final String finalIssuer = issuer;
            config = ssoConfigService.getEnabledSsoConfigs().stream()
                    .filter(c -> "JWT".equals(c.getSsoType()) && finalIssuer.equals(c.getJwtClientId()))
                    .findFirst()
                    .orElse(null);

            if (config == null) {
                System.err.println("❌ No *enabled* JWT config found with Client ID matching Issuer: " + issuer);
                throw new Exception("No enabled JWT configuration found for this token's issuer.");
            }

            System.out.println("✅ Loaded active config: " + config.getName());
            // --- End of New Fix ---

            // TODO: Now that you have 'config', you MUST validate the JWT signature
            // You need 'config.getJwtClientSecret()' or a public key from miniOrange
            // e.g., if (!jwtUtil.validateToken(jwtToken, config.getJwtClientSecret())) { ... }
            System.out.println("⚠️ WARNING: JWT signature is NOT being validated. This is insecure.");

            // 4. Extract user info from the claims we already have
            username = getClaimValue(jwtClaims, "username", "user", "preferred_username");
            email = getClaimValue(jwtClaims, "email", "mail", "sub");
            firstName = getClaimValue(jwtClaims, "first_name", "firstName", "given_name", "givenName");
            lastName = getClaimValue(jwtClaims, "last_name", "lastName", "family_name", "familyName");

            session.setAttribute("miniorange_token", jwtToken);

        } catch (Exception e) {
            System.err.println("❌ Error processing JWT: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "Failed to process JWT token: " + e.getMessage()); // <-- FIX: Changed to getMessage()
            model.addAttribute("allParams", allParams);
            return "sso-error";
        }

        System.out.println("\n📋 Extracted User Information:");
        System.out.println("   👤 Username: " + (username != null ? username : "NOT FOUND"));
        System.out.println("   📧 Email: " + (email != null ? email : "NOT FOUND"));
        System.out.println("   👤 First Name: " + (firstName != null ? firstName : "NOT FOUND"));
        System.out.println("   👤 Last Name: " + (lastName != null ? lastName : "NOT FOUND"));
        System.out.println("==========================================\n");

        // Validate if we have user information
        if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
            System.err.println("❌ Invalid SSO response - no user information found");
            model.addAttribute("error", "SSO Authentication failed: No user information found in JWT token");
            model.addAttribute("allParams", allParams);
            return "sso-error";
        }

        try {
            // Process user and generate our app's JWT token
            String appJwtToken = miniOrangeSsoService.processUserAfterSso(username, email, firstName, lastName);

            // Store JWT and user info in session
            session.setAttribute("jwt_token", appJwtToken);
            session.setAttribute("username", username != null ? username : email);
            session.setAttribute("authenticated_via", "sso-jwt");

            System.out.println("✅ SSO authentication successful for: " + (username != null ? username : email));

            // Redirect to success page
            model.addAttribute("jwtToken", appJwtToken);
            model.addAttribute("username", username != null ? username : email);
            model.addAttribute("email", email);

            return "home"; // <-- Changed from sso-success to home

        } catch (Exception e) {
            System.err.println("❌ SSO authentication failed during user processing: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "SSO authentication failed: " + e.getMessage());
            model.addAttribute("allParams", allParams);
            return "sso-error";
        }
    }

    /**
     * Decode JWT token and extract claims
     */
    private Map<String, Object> decodeJWT(String jwtToken) throws Exception {
        // Split the JWT token (header.payload.signature)
        String[] parts = jwtToken.split("\\.");

        if (parts.length < 2) {
            throw new Exception("Invalid JWT token format");
        }

        // Decode the payload (second part)
        String payload = parts[1];

        // Base64 decode
        byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
        String decodedPayload = new String(decodedBytes);

        // Don't log in production, but fine for debugging
        // System.out.println("🔓 Decoded JWT Payload: " + decodedPayload);

        // Parse JSON
        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = mapper.readValue(decodedPayload, Map.class);

        return claims;
    }

    /**
     * Get claim value from JWT claims map, trying multiple possible keys
     */
    private String getClaimValue(Map<String, Object> claims, String... possibleKeys) {
        for (String key : possibleKeys) {
            Object value = claims.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    /**
     * Helper method to extract parameter from multiple possible names
     */
    private String extractParameter(HttpServletRequest request, String... paramNames) {
        for (String paramName : paramNames) {
            String value = request.getParameter(paramName);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    /**
     * SSO Logout
     */
    @GetMapping("/logout")
    public void ssoLogout(HttpSession session, HttpServletResponse response) throws IOException {
        System.out.println("🚪 SSO Logout initiated");
        session.invalidate();
        response.sendRedirect("/");
        // Note: You may want to find the active config and redirect to config.getJwtLogoutUrl()
    }
}

