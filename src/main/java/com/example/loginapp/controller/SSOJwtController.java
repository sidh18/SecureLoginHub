package com.example.loginapp.controller;

import com.example.loginapp.config.TenantContext; // Import TenantContext
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

@Controller
@RequestMapping("/sso") // This was your JWT controller
public class SSOJwtController {

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    @Autowired
    private SsoConfigService ssoConfigService;

    /**
     * Initiate SSO Login - Redirect to MiniOrange (Now Tenant-Aware)
     */
    @GetMapping("/login") // This matches the login.html href
    public void initiateSSO(HttpServletResponse response, HttpSession session) throws IOException { // <-- ADD HttpSession

        // --- TENANT-AWARE ---
        Long organizationId = TenantContext.getCurrentOrganizationId();
        SsoConfig config = ssoConfigService.getEnabledSsoConfig("JWT", organizationId);

        if (config == null || !config.getEnabled()) {
            System.err.println("❌ JWT SSO not configured properly for organization ID: " + organizationId);
            response.sendRedirect("/?error=sso_not_configured");
            return;
        }

        String ssoUrl = config.getJwtSsoUrl();

        if (ssoUrl == null || ssoUrl.isEmpty()) {
            System.err.println("❌ SSO URL is not configured in SsoConfig (ID: " + config.getId() + ")");
            response.sendRedirect("/?error=sso_not_configured");
            return;
        }

        // --- RELAY STATE ---
        String relayState = "config_id=" + config.getId();
        String separator = ssoUrl.contains("?") ? "&" : "?";
        ssoUrl += separator + "RelayState=" + URLEncoder.encode(relayState, StandardCharsets.UTF_8);

        // --- FIX: STORE THE CONFIG ID IN THE SESSION ---
        // This is a reliable fallback if the IdP drops the RelayState parameter.
        session.setAttribute("sso_pending_config_id", config.getId());
        // --- END FIX ---

        System.out.println("\n🔐 ========== SSO LOGIN INITIATED ==========");
        System.out.println("🔗 Organization ID: " + organizationId);
        System.out.println("🔗 Config ID: " + config.getId());
        System.out.println("🔗 Stored config ID in session.");
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
        Map<String, String> allParams = logAllParameters(request);

        // Try to extract JWT token
        String jwtToken = extractParameter(request, "id_token", "token", "jwt", "access_token");
        String relayState = extractParameter(request, "RelayState", "state");

        if (jwtToken == null || jwtToken.isEmpty()) {
            System.err.println("❌ No JWT token (id_token) received");
            model.addAttribute("error", "SSO Authentication failed: No token received");
            return "sso-error";
        }

        // --- TENANT-AWARE & SESSION FIX ---
        Long configId = null;

        // 1. Try to get configId from RelayState (the preferred way)
        if (relayState != null && relayState.startsWith("config_id=")) {
            try {
                configId = Long.valueOf(relayState.substring(10));
                System.out.println("ℹ️ Found config ID in RelayState: " + configId);
            } catch (NumberFormatException e) { /* ignore */ }
        }

        // 2. If RelayState fails, try to get it from the session (the fallback)
        if (configId == null) {
            try {
                configId = (Long) session.getAttribute("sso_pending_config_id");
                if (configId != null) {
                    System.out.println("ℹ️ Found config ID in HTTP Session: " + configId);
                    // Clean up the session attribute
                    session.removeAttribute("sso_pending_config_id");
                }
            } catch (Exception e) {
                System.err.println("⚠️ Could not read config ID from session: " + e.getMessage());
            }
        }
        // --- END FIX ---

        if (configId == null) {
            System.err.println("❌ Invalid or missing RelayState AND no session fallback.");
            model.addAttribute("error", "SSO Authentication failed: Configuration not found (no state)");
            return "sso-error";
        }

        SsoConfig config;
        Long organizationId;
        try {
            // We can check any config, superadmin access not needed
            config = ssoConfigService.getSsoConfigById(configId, null);
            if (config.getOrganization() == null) {
                System.err.println("❌ SSO callback for a config with no organization: " + configId);
                model.addAttribute("error", "SSO Authentication failed: Configuration is not tied to an organization.");
                return "sso-error";
            }
            organizationId = config.getOrganization().getId(); // Get the org from the config
        } catch (Exception e) {
            System.err.println("❌ Config not found: " + configId);
            model.addAttribute("error", "SSO Authentication failed: Configuration not found");
            return "sso-error";
        }

        System.out.println("📋 Config ID: " + configId);
        System.out.println("📋 Organization ID: " + organizationId);

        String username = null;
        String email = null;
        String firstName = null;
        String lastName = null;

        try {
            System.out.println("\n🔑 JWT token received, decoding...");

            // TODO: Validate the JWT signature using the config's secret/key

            Map<String, Object> jwtClaims = decodeJWT(jwtToken);
            System.out.println("\n📋 Decoded JWT Claims:");
            jwtClaims.forEach((key, value) -> System.out.println("   ✓ " + key + " = " + value));

            // Extract user information from JWT claims
            username = getClaimValue(jwtClaims, "username", "user", "preferred_username");
            email = getClaimValue(jwtClaims, "email", "mail", "sub");
            firstName = getClaimValue(jwtClaims, "first_name", "firstName", "given_name", "givenName");
            lastName = getClaimValue(jwtClaims, "last_name", "lastName", "family_name", "familyName");

            session.setAttribute("miniorange_token", jwtToken);

        } catch (Exception e) {
            System.err.println("❌ Error decoding JWT: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "Failed to decode JWT token: " + e.getMessage());
            return "sso-error";
        }

        System.out.println("\n📋 Extracted User Information:");
        System.out.println("   👤 Username: " + (username != null ? username : "NOT FOUND"));
        System.out.println("   📧 Email: " + (email != null ? email : "NOT FOUND"));

        if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
            System.err.println("❌ Invalid SSO response - no user information found");
            model.addAttribute("error", "SSO Authentication failed: No user information found in JWT token");
            return "sso-error";
        }

        try {
            // Process user and generate our app's JWT token
            String appJwtToken = miniOrangeSsoService.processUserAfterSso(
                    username, email, firstName, lastName, organizationId
            );

            session.setAttribute("jwt_token", appJwtToken);
            session.setAttribute("username", username != null ? username : email);
            session.setAttribute("authenticated_via", "sso-jwt");

            System.out.println("✅ SSO authentication successful for: " + (username != null ? username : email));
            // --- FIX: Use redirect:/home ---
            // This tells Spring to send a 302 redirect to the browser,
            // which will then make a fresh GET request to /home.
            // This is cleaner and ensures the URL in the browser is correct.
            return "home";
            // --- END FIX ---

        } catch (Exception e) {
            System.err.println("❌ SSO authentication failed: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "SSO authentication failed: " + e.getMessage());
            return "sso-error";
        }
    }

    // --- Private Helper Methods ---

    private Map<String, String> logAllParameters(HttpServletRequest request) {
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
        return allParams;
    }

    private Map<String, Object> decodeJWT(String jwtToken) throws Exception {
        String[] parts = jwtToken.split("\\.");
        if (parts.length < 2) {
            throw new Exception("Invalid JWT token format");
        }
        String payload = parts[1];
        byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
        String decodedPayload = new String(decodedBytes);

        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = mapper.readValue(decodedPayload, Map.class);
        return claims;
    }

    private String getClaimValue(Map<String, Object> claims, String... possibleKeys) {
        for (String key : possibleKeys) {
            Object value = claims.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }


    private String extractParameter(HttpServletRequest request, String... paramNames) {
        for (String paramName : paramNames) {
            String value = request.getParameter(paramName);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    @GetMapping("/logout")
    public void ssoLogout(HttpSession session, HttpServletResponse response) throws IOException {
        System.out.println("🚪 SSO Logout initiated");
        session.invalidate();
        // This needs to be tenant-aware too, but for now, redirect to root
        response.sendRedirect("/");
    }
}

