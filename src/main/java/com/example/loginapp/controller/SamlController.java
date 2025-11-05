package com.example.loginapp.controller;

import com.example.loginapp.config.JwtUtil; // <-- IMPORT
import com.example.loginapp.security.CustomUserDetails;
import com.example.loginapp.config.TenantContext;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.model.user; // <-- IMPORT
import com.example.loginapp.service.UserService;
import com.example.loginapp.service.MiniOrangeSsoService;
import com.example.loginapp.service.SsoConfigService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority; // <-- IMPORT
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
import java.util.List; // <-- IMPORT

@Controller
@RequestMapping("/saml")
public class    SamlController {

    @Autowired
    private SsoConfigService ssoConfigService;

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    @Autowired
    private JwtUtil jwtUtil; // <-- INJECT JWTUTIL

    @Autowired
    private UserService userService;

    /**
     * Initiate SAML SSO (Now Tenant-Aware)
     */
    @GetMapping("/login")
    public void initiateSaml(HttpServletResponse response, HttpSession session) throws IOException { // <-- ADD HttpSession

        // --- TENANT-AWARE ---
        Long organizationId = TenantContext.getCurrentOrganizationId();

        SsoConfig config = ssoConfigService.getEnabledSsoConfig("SAML", organizationId);

        if (config == null || !config.getEnabled()) {
            System.err.println("❌ SAML SSO not configured properly for organization ID: " + organizationId);
            response.sendRedirect("/?error=saml_not_configured");
            return;
        }

        String ssoUrl = config.getSamlSsoUrl();

        if (ssoUrl == null || ssoUrl.isEmpty()) {
            System.err.println("❌ SAML SSO URL not configured");
            response.sendRedirect("/?error=saml_not_configured");
            return;
        }

        System.out.println("\n🔐 ========== SAML SSO LOGIN INITIATED ==========");
        System.out.println("🔗 Organization ID: " + organizationId);
        System.out.println("🔗 Config ID: " + config.getId());
        System.out.println("🔗 SSO URL: " + ssoUrl);

        // Generate SAML Request
        String samlRequest = generateSamlRequest(config);
        String encodedRequest = Base64.getEncoder().encodeToString(samlRequest.getBytes());
        String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8);

        // --- RELAY STATE ---
        String relayState = "config_id=" + config.getId();

        // Redirect to IDP with SAML Request
        String redirectUrl = ssoUrl + "?SAMLRequest=" + urlEncodedRequest +
                "&RelayState=" + URLEncoder.encode(relayState, StandardCharsets.UTF_8);

        // --- FIX: STORE THE CONFIG ID IN THE SESSION ---
        // This is a reliable fallback if the IdP drops the RelayState parameter.
        session.setAttribute("sso_pending_config_id", config.getId());
        // --- END FIX ---

        System.out.println("🔗 Stored config ID in session.");
        System.out.println("🔗 Redirecting to: " + redirectUrl);
        System.out.println("==========================================\n");

        response.sendRedirect(redirectUrl);
    }

    /**
     * SAML Assertion Consumer Service (ACS) - Handle SAML Response
     */
    @PostMapping("/acs")
    public String handleSamlResponse(HttpServletRequest request,
                                     HttpSession session,
                                     Model model) {

        System.out.println("\n🎯 ========== SAML ACS CALLBACK RECEIVED ==========");
        Map<String, String> allParams = logAllParameters(request);

        String samlResponse = request.getParameter("SAMLResponse");
        String relayState = request.getParameter("RelayState");

        if (samlResponse == null || samlResponse.isEmpty()) {
            System.err.println("❌ No SAML response received");
            model.addAttribute("error", "SAML Authentication failed: No SAML response received");
            model.addAttribute("allParams", allParams);
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
            model.addAttribute("error", "SAML Authentication failed: Configuration not found (no state)");
            return "sso-error";
        }

        try {
            SsoConfig config = ssoConfigService.getSsoConfigById(configId, null);
            if (config.getOrganization() == null) {
                System.err.println("❌ SSO callback for a config with no organization: " + configId);
                model.addAttribute("error", "SSO Authentication failed: Configuration is not tied to an organization.");
                return "sso-error";
            }
            Long organizationId = config.getOrganization().getId(); // Get the org from the config

            // TODO: Validate the SAML response (e.g., check signature with config.getSamlX509Certificate())
            // This is a CRITICAL security step.
            // For now, we are just parsing.

            // Decode and parse SAML Response
            Map<String, String> userData = parseSamlResponse(samlResponse);

            System.out.println("\n📋 Extracted User Information:");
            System.out.println("   👤 Username: " + userData.getOrDefault("username", "NOT FOUND"));
            System.out.println("   📧 Email: " + userData.getOrDefault("email", "NOT FOUND"));

            String username = userData.get("username");
            String email = userData.get("email");
            String firstName = userData.get("firstName");
            String lastName = userData.get("lastName");

            if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
                System.err.println("❌ Invalid SAML response - no user information found");
                model.addAttribute("error", "SAML Authentication failed: No user information found in SAML response");
                return "sso-error";
            }

            // --- FIX: Get the user object from the service ---
            // 1. Get the user identifier (username) from the SSO service.
            String userIdentifier = miniOrangeSsoService.processUserAfterSso(
                    username, email, firstName, lastName, organizationId
            );

            // 2. Use the identifier to fetch the full user object from our local UserService
            user loggedInUser = userService.findByUsername(userIdentifier, organizationId);

            // 3. Add a null check for security
            if (loggedInUser == null) {
                System.err.println("❌ SAML user '" + userIdentifier + "' not found in local database for org " + organizationId);
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
            session.setAttribute("authenticated_via", "saml");

            System.out.println("✅ SAML authentication successful for: " + userDetails.getUsername());

            // --- FIX: Role-based redirect ---
            if ("ROLE_ADMIN".equals(loggedInUser.getRole())) {
                return "redirect:/admin/dashboard"; // Redirect Tenant Admins
            } else {
                return "redirect:/home"; // Redirect regular users
            }
            // --- END FIX ---

        } catch (Exception e) {
            System.err.println("❌ SAML authentication failed: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "SAML authentication failed: " + e.getMessage());
            return "sso-error";
        }
    }

    // --- Private Helper Methods (Unchanged) ---

    private Map<String, String> logAllParameters(HttpServletRequest request) {
        Map<String, String> allParams = new HashMap<>();
        Enumeration<String> paramNames = request.getParameterNames();
        System.out.println("\n📦 All parameters received:");
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String paramValue = request.getParameter(paramName);
            allParams.put(paramName, paramValue);
            if (paramName.equals("SAMLResponse")) {
                System.out.println("   ✓ " + paramName + " = [SAML RESPONSE PRESENT - Length: " + paramValue.length() + "]");
            } else {
                System.out.println("   ✓ " + paramName + " = " + paramValue);
            }
        }
        return allParams;
    }

    private String generateSamlRequest(SsoConfig config) {
        // This is a minimal, unsigned SAML request.
        // For production, you'd use a library like OpenSAML to sign it.
        String entityId = config.getSamlEntityId();
        String acsUrl = config.getSamlAcsUrl();
        StringBuilder samlRequest = new StringBuilder();
        samlRequest.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
        samlRequest.append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
        samlRequest.append("ID=\"_" + java.util.UUID.randomUUID().toString() + "\" ");
        samlRequest.append("Version=\"2.0\" ");
        samlRequest.append("IssueInstant=\"" + java.time.Instant.now().toString() + "\" ");
        samlRequest.append("AssertionConsumerServiceURL=\"" + acsUrl + "\">");
        samlRequest.append("<saml:Issuer>" + entityId + "</saml:Issuer>");
        samlRequest.append("<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" />");
        samlRequest.append("</samlp:AuthnRequest>");
        return samlRequest.toString();
    }

    private Map<String, String> parseSamlResponse(String samlResponse) throws Exception {
        // WARNING: This is a highly insecure, naive SAML parser.
        // It does NOT validate signatures. DO NOT use in production.
        // It's for debugging the attribute flow only.
        Map<String, String> userData = new HashMap<>();
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
            String decodedResponse = new String(decodedBytes);
            System.out.println("🔓 Decoded SAML Response (first 500 chars): " +
                    decodedResponse.substring(0, Math.min(500, decodedResponse.length())));

            // Find NameID (often the email or username)
            if (decodedResponse.contains("<saml:NameID")) {
                String nameId = extractXmlValue(decodedResponse, "<saml:NameID", "</saml:NameID>");
                userData.put("username", nameId);
                userData.put("email", nameId); // Default email to NameID
            }
            // Find attributes
            userData.put("firstName", extractAttribute(decodedResponse, "FirstName", "first_name", "givenName"));
            userData.put("lastName", extractAttribute(decodedResponse, "LastName", "last_name", "familyName"));
            String email = extractAttribute(decodedResponse, "Email", "email", "mail");
            if (email != null && !email.isEmpty()) {
                userData.put("email", email); // Overwrite with specific email if found
            }
        } catch (Exception e) {
            System.err.println("Error parsing SAML response: " + e.getMessage());
            throw e;
        }
        return userData;
    }

    private String extractXmlValue(String xml, String startTag, String endTag) {
        try {
            int start = xml.indexOf(startTag);
            if (start == -1) return null;
            start = xml.indexOf(">", start) + 1;
            int end = xml.indexOf(endTag, start);
            if (end == -1) return null;
            return xml.substring(start, end).trim();
        } catch (Exception e) {
            return null;
        }
    }

    private String extractAttribute(String xml, String... attributeNames) {
        for (String attrName : attributeNames) {
            // Case-insensitive search for attribute name
            String pattern = "Name=\"" + attrName + "\"";
            int attrPos = xml.toLowerCase().indexOf(pattern.toLowerCase());

            if (attrPos != -1) {
                // Find the <saml:AttributeValue> tag *after* this attribute name
                int valueStart = xml.indexOf("<saml:AttributeValue", attrPos);
                if (valueStart != -1) {
                    valueStart = xml.indexOf(">", valueStart) + 1;
                    int valueEnd = xml.indexOf("</saml:AttributeValue>", valueStart);
                    if (valueEnd != -1) {
                        return xml.substring(valueStart, valueEnd).trim();
                    }
                }
            }
        }
        return null;
    }
}