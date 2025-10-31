package com.example.loginapp.controller;

import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.service.MiniOrangeSsoService;
import com.example.loginapp.service.SsoConfigService;
import com.fasterxml.jackson.databind.ObjectMapper;
// Removed insecure SSL imports
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
// Removed insecure HTTP client imports
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
// Removed reactor-netty imports

// Removed SSL Exception import
import java.io.IOException;
import java.net.URLEncoder; // Import URLEncoder
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/oauth")
public class OAuthController {

    @Autowired
    private SsoConfigService ssoConfigService;

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    private final WebClient webClient;

    /**
     * Constructor
     * --- FIX: Reverted to a standard, secure WebClient ---
     * The PKIX error was solved by updating the JDK's cacerts file,
     * so the insecure workaround is no longer needed.
     */
    public OAuthController() {
        System.out.println("✅ Initializing standard, secure WebClient for OAuthController.");
        this.webClient = WebClient.builder().build();
    }

    /**
     * Initiate OAuth SSO
     */
    @GetMapping("/login/{configId}")
    public void initiateOAuth(@PathVariable Long configId,
                              HttpServletResponse response) throws IOException {

        SsoConfig config = ssoConfigService.getSsoConfigById(configId);

        if (config == null || !config.getEnabled() || !"OAUTH".equals(config.getSsoType())) {
            System.err.println("❌ OAuth SSO not configured properly for config ID: " + configId);
            response.sendRedirect("/?error=oauth_not_configured");
            return;
        }

        String authUrl = config.getOauthAuthorizationUrl();
        String clientId = config.getOauthClientId();
        String callbackUrl = config.getOauthCallbackUrl();

        if (authUrl == null || clientId == null || callbackUrl == null) {
            System.err.println("❌ OAuth configuration incomplete");
            response.sendRedirect("/?error=oauth_not_configured");
            return;
        }

        System.out.println("\n🔐 ========== OAUTH SSO LOGIN INITIATED ==========");
        System.out.println("🔗 Config ID: " + configId);
        System.out.println("🔗 Config Name: " + config.getName());

        // --- Use 'state' parameter for config_id ---
        String state = "config_id=" + configId;

        // Build authorization URL
        String separator = authUrl.contains("?") ? "&" : "?";
        String redirectUrl = authUrl + separator +
                "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&scope=openid profile email" +
                "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8); // Pass config_id in state

        System.out.println("🔗 Redirecting to: " + redirectUrl);
        System.out.println("==========================================\n");

        response.sendRedirect(redirectUrl);
    }

    /**
     * OAuth Callback - Handle authorization code
     */
    @GetMapping("/callback")
    public String handleOAuthCallback(HttpServletRequest request,
                                      @RequestParam(required = false) String code,
                                      // --- Read config_id from 'state' ---
                                      @RequestParam(required = false) String state,
                                      @RequestParam(required = false) String error,
                                      HttpSession session,
                                      Model model) {

        System.out.println("\n🎯 ========== OAUTH CALLBACK RECEIVED ==========");

        if (error != null) {
            System.err.println("❌ OAuth error: " + error);
            model.addAttribute("error", "OAuth Authentication failed: " + error);
            return "sso-error";
        }

        if (code == null) {
            System.err.println("❌ No authorization code received");
            model.addAttribute("error", "OAuth Authentication failed: No authorization code received");
            return "sso-error";
        }

        // --- Extract config_id from state ---
        Long configId = null;
        if (state != null && state.startsWith("config_id=")) {
            try {
                configId = Long.valueOf(state.substring(10));
            } catch (NumberFormatException e) {
                System.err.println("❌ Invalid state parameter format: " + state);
            }
        }

        if (configId == null) {
            System.err.println("❌ No config ID in callback state");
            model.addAttribute("error", "OAuth Authentication failed: Configuration not found (no state)");
            return "sso-error";
        }

        SsoConfig config = ssoConfigService.getSsoConfigById(configId);
        if (config == null) {
            System.err.println("❌ Config not found: " + configId);
            model.addAttribute("error", "OAuth Authentication failed: Configuration not found");
            return "sso-error";
        }

        System.out.println("📋 Authorization code received: " + code.substring(0, Math.min(20, code.length())) + "...");
        System.out.println("📋 Config ID: " + configId);

        try {
            // Exchange code for token
            Map<String, String> tokenResponse = exchangeCodeForToken(config, code); // Pass config and code
            String accessToken = tokenResponse.get("access_token");

            if (accessToken == null) {
                throw new Exception("Failed to get access token. Response from token endpoint: " + tokenResponse);
            }

            System.out.println("✅ Access token received");

            // Get user info
            Map<String, Object> userInfo = getUserInfo(config, accessToken);

            System.out.println("\n📋 User Info received:");
            userInfo.forEach((key, value) -> System.out.println("   ✓ " + key + " = " + value));

            String username = extractUserInfoValue(userInfo, "username", "preferred_username", "name");
            String email = extractUserInfoValue(userInfo, "email", "mail");
            String firstName = extractUserInfoValue(userInfo, "given_name", "first_name", "firstName");
            String lastName = extractUserInfoValue(userInfo, "family_name", "last_name", "lastName");

            System.out.println("\n📋 Extracted User Information:");
            System.out.println("   👤 Username: " + username);
            System.out.println("   📧 Email: " + email);
            System.out.println("   👤 First Name: " + firstName);
            System.out.println("   👤 Last Name: " + lastName);
            System.out.println("==========================================\n");

            // Validate user data
            if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
                System.err.println("❌ Invalid OAuth response - no user information found");
                model.addAttribute("error", "OAuth Authentication failed: No user information found");
                return "sso-error";
            }

            // Process user and generate JWT
            String appJwtToken = miniOrangeSsoService.processUserAfterSso(username, email, firstName, lastName);

            // Store in session
            session.setAttribute("jwt_token", appJwtToken);
            session.setAttribute("username", username != null ? username : email);
            session.setAttribute("authenticated_via", "oauth");

            System.out.println("✅ OAuth authentication successful for: " + (username != null ? username : email));

            // Redirect to success page
            model.addAttribute("jwtToken", appJwtToken);
            model.addAttribute("username", username != null ? username : email);
            model.addAttribute("email", email);

            return "home"; // Assuming "home" is your success page

        } catch (Exception e) {
            System.err.println("❌ OAuth authentication failed: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "OAuth authentication failed: " + e.getMessage());
            return "sso-error";
        }
    }

    /**
     * Exchange authorization code for access token
     */
    private Map<String, String> exchangeCodeForToken(SsoConfig config, String code) throws Exception {
        String tokenUrl = config.getOauthTokenUrl();
        String clientId = config.getOauthClientId();
        String clientSecret = config.getOauthClientSecret();
        String callbackUrl = config.getOauthCallbackUrl(); // Get callbackUrl from config

        // Build Basic Auth header
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

        // --- FIX: URL-encode all form data parameters ---
        String formData = "grant_type=authorization_code" +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8) +
                "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

        try {
            // Use the standard, secure webClient
            Map<String, Object> response = webClient.post()
                    .uri(tokenUrl)
                    .header("Authorization", "Basic " + encodedAuth)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .bodyValue(formData)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            Map<String, String> result = new HashMap<>();
            if (response != null) {
                response.forEach((key, value) -> result.put(key, value != null ? value.toString() : null));
            }
            return result;

        } catch (Exception e) {
            System.err.println("Error exchanging code for token: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Get user info using access token
     */
    private Map<String, Object> getUserInfo(SsoConfig config, String accessToken) throws Exception {
        String userInfoUrl = config.getOauthUserInfoUrl();

        if (userInfoUrl == null || userInfoUrl.isEmpty()) {
            throw new Exception("User info URL not configured");
        }

        try {
            // Use the standard, secure webClient
            return webClient.get()
                    .uri(userInfoUrl)
                    .header("Authorization", "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();
        } catch (Exception e) {
            System.err.println("Error getting user info: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Extract user info value from multiple possible keys
     */
    private String extractUserInfoValue(Map<String, Object> userInfo, String... keys) {
        for (String key : keys) {
            Object value = userInfo.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }
}

