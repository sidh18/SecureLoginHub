package com.example.loginapp.controller;

import com.example.loginapp.config.JwtUtil; // <-- IMPORT
import com.example.loginapp.config.TenantContext;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.model.user; // <-- IMPORT
import com.example.loginapp.security.CustomUserDetails; // <-- IMPORT
import com.example.loginapp.service.MiniOrangeSsoService;
import com.example.loginapp.service.SsoConfigService;
import com.example.loginapp.service.UserService; // <-- IMPORT USER SERVICE
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.core.authority.SimpleGrantedAuthority; // <-- IMPORT
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.List; // <-- IMPORT

@Controller
@RequestMapping("/oauth")
public class OAuthController {

    @Autowired
    private SsoConfigService ssoConfigService;

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    @Autowired
    private UserService userService; // <-- INJECT USER SERVICE

    @Autowired
    private JwtUtil jwtUtil; // <-- INJECT JWTUTIL

    private final WebClient webClient;

    /**
     * Revert to a STANDARD, SECURE WebClient.
     * We will NOT use the insecure workaround anymore.
     * If PKIX errors happen, the user must fix their cacerts.
     */
    public OAuthController() {
        System.out.println("✅ Building secure, default WebClient.");
        this.webClient = WebClient.builder().build();
    }

    /**
     * Initiate OAuth SSO (Now Tenant-Aware)
     */
    @GetMapping("/login") // Removed {configId}
    public void initiateOAuth(HttpServletResponse response, HttpSession session) throws IOException { // <-- ADD HttpSession

        // --- TENANT-AWARE ---
        Long organizationId = TenantContext.getCurrentOrganizationId();
        SsoConfig config = ssoConfigService.getEnabledSsoConfig("OAUTH", organizationId);

        if (config == null || !config.getEnabled()) {
            System.err.println("❌ OAuth SSO not configured properly for organization ID: " + organizationId);
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
        System.out.println("🔗 Organization ID: " + organizationId);
        System.out.println("🔗 Config ID: " + config.getId());

        // --- STATE PARAMETER ---
        // Pass the configId in the state so we know which config to use on callback
        String state = "config_id=" + config.getId();

        // --- FIX: STORE THE CONFIG ID IN THE SESSION ---
        // This is a reliable fallback if the IdP drops the state parameter.
        session.setAttribute("sso_pending_config_id", config.getId());
        // --- END FIX ---

        System.out.println("🔗 Stored config ID in session.");

        // Build authorization URL
        String separator = authUrl.contains("?") ? "&" : "?";
        String redirectUrl = authUrl + separator +
                "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&scope=openid profile email" +
                "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

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
                                      @RequestParam(required = false) String state, // Read state
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

        // --- TENANT-AWARE & SESSION FIX ---
        Long configId = null;

        // 1. Try to get configId from state (the preferred way)
        if (state != null && state.startsWith("config_id=")) {
            try {
                configId = Long.valueOf(state.substring(10));
                System.out.println("ℹ️ Found config ID in state: " + configId);
            } catch (NumberFormatException e) { /* ignore */ }
        }

        // 2. If state fails, try to get it from the session (the fallback)
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

        // 3. Check again
        if (configId == null) {
            System.err.println("❌ Invalid or missing state AND no session fallback.");
            model.addAttribute("error", "OAuth Authentication failed: Configuration not found (no state)");
            return "sso-error";
        }
        // --- END FIX ---

        SsoConfig config;
        Long organizationId;
        try {
            config = ssoConfigService.getSsoConfigById(configId, null);
            if (config.getOrganization() == null) {
                System.err.println("❌ SSO callback for a config with no organization: " + configId);
                model.addAttribute("error", "SSO Authentication failed: Configuration is not tied to an organization.");
                return "sso-error";
            }
            organizationId = config.getOrganization().getId();
        } catch (Exception e) {
            System.err.println("❌ Config not found: " + configId);
            model.addAttribute("error", "OAuth Authentication failed: Configuration not found");
            return "sso-error";
        }

        System.out.println("📋 Authorization code received: " + code.substring(0, Math.min(20, code.length())) + "...");
        System.out.println("📋 Config ID: " + configId);
        System.out.println("📋 Organization ID: " + organizationId);

        try {
            // Exchange code for token
            Map<String, String> tokenResponse = exchangeCodeForToken(config, code);
            String accessToken = tokenResponse.get("access_token");

            if (accessToken == null) {
                throw new Exception("Failed to get access token");
            }

            System.out.println("✅ Access token received");

            // Get user info
            Map<String, Object> userInfo = getUserInfo(config, accessToken);

            System.out.println("\n📋 User Info received:");
            userInfo.forEach((key, value) -> System.out.println("    ✓ " + key + " = " + value));

            String username = extractUserInfoValue(userInfo, "username", "preferred_username", "name");
            String email = extractUserInfoValue(userInfo, "email", "mail");
            String firstName = extractUserInfoValue(userInfo, "given_name", "first_name", "firstName");
            String lastName = extractUserInfoValue(userInfo, "family_name", "last_name", "lastName");

            if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
                System.err.println("❌ Invalid OAuth response - no user information found");
                model.addAttribute("error", "OAuth Authentication failed: No user information found");
                return "sso-error";
            }

            // --- FIX: Get the user object from the service ---
            // 1. Get the user identifier (username) from the SSO service.
            String userIdentifier = miniOrangeSsoService.processUserAfterSso(
                    username, email, firstName, lastName, organizationId
            );

            // 2. Use the identifier to fetch the full user object from our local UserService
            // --- FIX: Pass organizationId to findByUsername ---
            user loggedInUser = userService.findByUsername(userIdentifier, organizationId);

            // 3. Add a null check for security
            if (loggedInUser == null) {
                System.err.println("❌ SSO user '" + userIdentifier + "' not found in local database for org " + organizationId);
                model.addAttribute("error", "Authenticated user '" + userIdentifier + "' is not registered in this application.");
                return "sso-error";
            }

            // --- FIX: Generate JWT and session data here ---
            CustomUserDetails userDetails = new CustomUserDetails(
                    loggedInUser.getUsername(),
                    loggedInUser.getPassword(), // This is the hashed password, which is fine
                    List.of(new SimpleGrantedAuthority(loggedInUser.getRole())),
                    (loggedInUser.getOrganization() != null) ? loggedInUser.getOrganization().getId() : null
            );

            String appJwtToken = jwtUtil.generateToken(userDetails);

            session.setAttribute("jwt_token", appJwtToken);
            session.setAttribute("username", userDetails.getUsername());
            session.setAttribute("authenticated_via", "oauth");

            // --- FIX: Removed stray "SsoConfigService" text ---
            System.out.println("✅ OAuth authentication successful for: " + userDetails.getUsername());

            // --- FIX: Role-based redirect ---
            if ("ROLE_ADMIN".equals(loggedInUser.getRole())) {
                return "redirect:/admin/dashboard"; // Redirect Tenant Admins
            } else {
                return "redirect:/home"; // Redirect regular users
            }
            // --- END FIX ---

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
        String callbackUrl = config.getOauthCallbackUrl(); // Use the one from config

        // Build Basic Auth header
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

        // Prepare form data (MUST be URL-encoded)
        String formData = "grant_type=authorization_code" +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8) +
                "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

        try {
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