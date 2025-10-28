package com.example.loginapp.controller;

import com.example.loginapp.service.MiniOrangeSsoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/sso")
public class SSOJwtController {

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    /**
     * Initiate SSO Login - Redirect to MiniOrange
     */
    @GetMapping("/login")
    public void initiateSSO(HttpServletResponse response) throws IOException {
        String ssoUrl = miniOrangeSsoService.getSsoLoginUrl();
        System.out.println("\n🔐 ========== SSO LOGIN INITIATED ==========");
        System.out.println("🔗 Redirecting to MiniOrange SSO: " + ssoUrl);
        System.out.println("==========================================\n");
        response.sendRedirect(ssoUrl);
    }

    /**
     * SSO Callback - Handle response from MiniOrange
     */
    @RequestMapping(value = "/callback", method = {RequestMethod.GET, RequestMethod.POST})
    public String handleCallback(
            HttpServletRequest request,
            HttpSession session,
            Model model) {

        System.out.println("\n🎯 ========== SSO CALLBACK RECEIVED ==========");
        System.out.println("📋 Request Method: " + request.getMethod());
        System.out.println("📋 Request URL: " + request.getRequestURL());

        // Log all parameters received
        Map<String, String> allParams = new HashMap<>();
        Enumeration<String> paramNames = request.getParameterNames();

        System.out.println("\n📦 All parameters received:");
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String paramValue = request.getParameter(paramName);
            allParams.put(paramName, paramValue);

            // Don't print full JWT in logs for security
            if (paramName.equals("id_token") || paramName.equals("token") || paramName.equals("jwt")) {
                System.out.println("   ✓ " + paramName + " = [JWT TOKEN PRESENT - Length: " + paramValue.length() + "]");
            } else {
                System.out.println("   ✓ " + paramName + " = " + paramValue);
            }
        }

        // Try to extract JWT token
        String jwtToken = extractParameter(request, "id_token", "token", "jwt", "access_token");

        String username = null;
        String email = null;
        String firstName = null;
        String lastName = null;

        // If we have a JWT token, decode it to extract user info
        if (jwtToken != null && !jwtToken.isEmpty()) {
            System.out.println("\n🔑 JWT token received, decoding...");

            try {
                Map<String, Object> jwtClaims = decodeJWT(jwtToken);

                System.out.println("\n📋 Decoded JWT Claims:");
                for (Map.Entry<String, Object> entry : jwtClaims.entrySet()) {
                    System.out.println("   ✓ " + entry.getKey() + " = " + entry.getValue());
                }

                // Extract user information from JWT claims
                username = getClaimValue(jwtClaims, "username", "user", "preferred_username");
                email = getClaimValue(jwtClaims, "email", "mail", "sub");
                firstName = getClaimValue(jwtClaims, "first_name", "firstName", "given_name", "givenName");
                lastName = getClaimValue(jwtClaims, "last_name", "lastName", "family_name", "familyName");

                // Store the MiniOrange token
                session.setAttribute("miniorange_token", jwtToken);

            } catch (Exception e) {
                System.err.println("❌ Error decoding JWT: " + e.getMessage());
                e.printStackTrace();
                model.addAttribute("error", "Failed to decode JWT token: " + e.getMessage());
                model.addAttribute("allParams", allParams);
                return "sso-error";
            }
        } else {
            // Try to extract from request parameters (fallback)
            username = extractParameter(request, "username", "user", "name", "sub", "preferred_username", "Username");
            email = extractParameter(request, "email", "mail", "emailAddress", "Email");
            firstName = extractParameter(request, "firstName", "given_name", "givenName", "FirstName");
            lastName = extractParameter(request, "lastName", "family_name", "familyName", "LastName");
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
            model.addAttribute("error", "SSO Authentication failed: No user information found in JWT token or parameters");
            model.addAttribute("allParams", allParams);
            return "sso-error";
        }

        try {
            // Process user and generate our app's JWT token
            String appJwtToken = miniOrangeSsoService.processUserAfterSso(username, email, firstName, lastName);

            // Store JWT and user info in session
            session.setAttribute("jwt_token", appJwtToken);
            session.setAttribute("username", username != null ? username : email);
            session.setAttribute("authenticated_via", "sso");

            System.out.println("✅ SSO authentication successful for: " + (username != null ? username : email));

            // Redirect to success page
            model.addAttribute("jwtToken", appJwtToken);
            model.addAttribute("username", username != null ? username : email);
            model.addAttribute("email", email);

            return "home";

        } catch (Exception e) {
            System.err.println("❌ SSO authentication failed: " + e.getMessage());
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

        System.out.println("🔓 Decoded JWT Payload: " + decodedPayload);

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

        // Clear session
        session.invalidate();

        // Redirect to MiniOrange logout
        String logoutUrl = miniOrangeSsoService.getSsoLogoutUrl();
        System.out.println("🔗 Redirecting to MiniOrange logout: " + logoutUrl);
        response.sendRedirect(logoutUrl);
    }
}