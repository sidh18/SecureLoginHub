package com.example.loginapp.controller;

import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.service.MiniOrangeSsoService;
import com.example.loginapp.service.SsoConfigService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;

@Controller
@RequestMapping("/saml")
public class SamlController {

    @Autowired
    private SsoConfigService ssoConfigService;

    @Autowired
    private MiniOrangeSsoService miniOrangeSsoService;

    /**
     * Initiate SAML SSO (SP-Initiated)
     */
    @GetMapping("/login/{configId}")
    public void initiateSaml(@PathVariable Long configId, HttpServletResponse response) throws Exception {

        SsoConfig config = ssoConfigService.getSsoConfigById(configId);
        if (config == null || !config.getEnabled() || !"SAML".equals(config.getSsoType())) {
            response.sendRedirect("/?error=saml_not_configured");
            return;
        }

        String ssoUrl = config.getSamlSsoUrl();     // IdP SSO URL
        String acsUrl = config.getSamlAcsUrl();     // Your ACS: http://localhost:8190/saml/acs

        if (ssoUrl == null || ssoUrl.isEmpty() || acsUrl == null || acsUrl.isEmpty()) {
            response.sendRedirect("/?error=saml_not_configured");
            return;
        }

        // Generate SAML AuthnRequest XML
        String samlRequestXml = generateSamlRequest(config);

        // DEFLATE + Base64 + URL-encode
        String encodedRequest = deflateAndEncode(samlRequestXml);
        String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8);

        // RelayState: send configId back
        String relayState = URLEncoder.encode(acsUrl + "?config_id=" + configId, StandardCharsets.UTF_8);

        String redirectUrl = ssoUrl + "?SAMLRequest=" + urlEncodedRequest + "&RelayState=" + relayState;

        System.out.println("Redirecting to miniOrange: " + redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    /**
     * SAML Assertion Consumer Service (ACS)
     */
    @PostMapping("/acs")
    public String handleSamlResponse(HttpServletRequest request, HttpSession session, Model model) {

        String samlResponse = request.getParameter("SAMLResponse");
        String relayState = request.getParameter("RelayState");

        if (samlResponse == null || samlResponse.isEmpty()) {
            model.addAttribute("error", "No SAML response received");
            return "sso-error";
        }

        // Extract config_id from RelayState
        Long configId = null;
        if (relayState != null && relayState.contains("config_id=")) {
            try {
                String[] parts = relayState.split("config_id=");
                configId = Long.parseLong(parts[1].split("&")[0]);
            } catch (Exception e) {
                // ignore
            }
        }

        try {
            Map<String, String> userData = parseSamlResponse(samlResponse);

            String email = userData.get("email");
            String username = userData.get("username");
            String firstName = userData.get("firstName");
            String lastName = userData.get("lastName");

            if (email == null || email.isEmpty()) {
                model.addAttribute("error", "Email not found in SAML response");
                return "sso-error";
            }

            String jwt = miniOrangeSsoService.processUserAfterSso(username, email, firstName, lastName);

            session.setAttribute("jwt_token", jwt);
            session.setAttribute("username", email);
            session.setAttribute("authenticated_via", "saml");

            return "home";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "SAML parse failed: " + e.getMessage());
            return "sso-error";
        }
    }

    // === HELPER: DEFLATE + BASE64 ===
    private String deflateAndEncode(String xml) throws Exception {
        byte[] input = xml.getBytes(StandardCharsets.UTF_8);
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        deflater.setInput(input);
        deflater.finish();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            baos.write(buffer, 0, count);
        }
        deflater.end();

        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    // === HELPER: GENERATE SAML REQUEST XML ===
    private String generateSamlRequest(SsoConfig config) {
        String entityId = config.getSamlEntityId();
        String acsUrl = config.getSamlAcsUrl();
        String ssoUrl = config.getSamlSsoUrl();

        return """
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                ID="_%s"
                                Version="2.0"
                                IssueInstant="%s"
                                Destination="%s"
                                AssertionConsumerServiceURL="%s">
                <saml:Issuer>%s</saml:Issuer>
                <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
            </samlp:AuthnRequest>
            """.formatted(
                java.util.UUID.randomUUID().toString(),
                java.time.Instant.now().toString(),
                ssoUrl,
                acsUrl,
                entityId
        );
    }

    // === HELPER: PARSE SAML RESPONSE ===
    private Map<String, String> parseSamlResponse(String samlResponse) throws Exception {
        Map<String, String> userData = new HashMap<>();
        byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
        String decodedResponse = new String(decodedBytes, StandardCharsets.UTF_8);

        // Extract NameID (usually email)
        String nameId = extractXmlValue(decodedResponse, "<saml:NameID", "</saml:NameID>");
        if (nameId != null) {
            userData.put("email", nameId);
            userData.put("username", nameId);
        }

        // Extract attributes
        userData.put("firstName", extractAttribute(decodedResponse, "FirstName", "first_name", "givenName"));
        userData.put("lastName", extractAttribute(decodedResponse, "LastName", "last_name", "familyName"));

        String email = extractAttribute(decodedResponse, "Email", "email", "mail");
        if (email != null && !email.isEmpty()) {
            userData.put("email", email);
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

    private String extractAttribute(String xml, String... names) {
        for (String name : names) {
            String pattern = "Name=\"" + name + "\"";
            int pos = xml.indexOf(pattern);
            if (pos != -1) {
                int valueStart = xml.indexOf("<saml:AttributeValue", pos);
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





//package com.example.loginapp.controller;
//
//import com.example.loginapp.model.SsoConfig;
//import com.example.loginapp.service.MiniOrangeSsoService;
//import com.example.loginapp.service.SsoConfigService;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import jakarta.servlet.http.HttpSession;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.*;
//
//import java.io.IOException;
//import java.net.URLEncoder;
//import java.nio.charset.StandardCharsets;
//import java.util.Base64;
//import java.util.Enumeration;
//import java.util.HashMap;
//import java.util.Map;
//
//@Controller
//@RequestMapping("/saml")
//public class SamlController {
//
//    @Autowired
//    private SsoConfigService ssoConfigService;
//
//    @Autowired
//    private MiniOrangeSsoService miniOrangeSsoService;
//
//    /**
//     * Initiate SAML SSO
//     */
//    @GetMapping("/login/{configId}")
//    public void initiateSaml(@PathVariable Long configId,
//                             HttpServletResponse response) throws IOException {
//
//        SsoConfig config = ssoConfigService.getSsoConfigById(configId);
//
//        if (config == null || !config.getEnabled() || !"SAML".equals(config.getSsoType())) {
//            System.err.println("❌ SAML SSO not configured properly for config ID: " + configId);
//            response.sendRedirect("/?error=saml_not_configured");
//            return;
//        }
//
//        String ssoUrl = config.getSamlSsoUrl();
//        String acsUrl = config.getSamlAcsUrl();
//
//        if (ssoUrl == null || ssoUrl.isEmpty()) {
//            System.err.println("❌ SAML SSO URL not configured");
//            response.sendRedirect("/?error=saml_not_configured");
//            return;
//        }
//
//        System.out.println("\n🔐 ========== SAML SSO LOGIN INITIATED ==========");
//        System.out.println("🔗 Config ID: " + configId);
//        System.out.println("🔗 SSO URL: " + ssoUrl);
//        System.out.println("🔗 ACS URL: " + acsUrl);
//
//        // Generate SAML Request
//        String samlRequest = generateSamlRequest(config);
//        String encodedRequest = Base64.getEncoder().encodeToString(samlRequest.getBytes());
//        String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8);
//
//        // Redirect to IDP with SAML Request
//        String redirectUrl = ssoUrl + "?SAMLRequest=" + urlEncodedRequest;
//        if (acsUrl != null && !acsUrl.isEmpty()) {
//            redirectUrl += "&RelayState=" + URLEncoder.encode(acsUrl + "?config_id=" + configId, StandardCharsets.UTF_8);
//        }
//
//        System.out.println("🔗 Redirecting to: " + redirectUrl);
//        System.out.println("==========================================\n");
//
//        response.sendRedirect(redirectUrl);
//    }
//
//    /**
//     * SAML Assertion Consumer Service (ACS) - Handle SAML Response
//     */
//    @PostMapping("/acs")
//    public String handleSamlResponse(HttpServletRequest request,
//                                     HttpSession session,
//                                     Model model) {
//
//        System.out.println("\n🎯 ========== SAML ACS CALLBACK RECEIVED ==========");
//
//        // Log all parameters
//        Map<String, String> allParams = new HashMap<>();
//        Enumeration<String> paramNames = request.getParameterNames();
//
//        System.out.println("\n📦 All parameters received:");
//        while (paramNames.hasMoreElements()) {
//            String paramName = paramNames.nextElement();
//            String paramValue = request.getParameter(paramName);
//            allParams.put(paramName, paramValue);
//
//            if (paramName.equals("SAMLResponse")) {
//                System.out.println("   ✓ " + paramName + " = [SAML RESPONSE PRESENT - Length: " + paramValue.length() + "]");
//            } else {
//                System.out.println("   ✓ " + paramName + " = " + paramValue);
//            }
//        }
//
//        String samlResponse = request.getParameter("SAMLResponse");
//        String relayState = request.getParameter("RelayState");
//
//        if (samlResponse == null || samlResponse.isEmpty()) {
//            System.err.println("❌ No SAML response received");
//            model.addAttribute("error", "SAML Authentication failed: No SAML response received");
//            model.addAttribute("allParams", allParams);
//            return "sso-error";
//        }
//
//        try {
//            // Decode and parse SAML Response
//            Map<String, String> userData = parseSamlResponse(samlResponse);
//
//            System.out.println("\n📋 Extracted User Information:");
//            System.out.println("   👤 Username: " + userData.getOrDefault("username", "NOT FOUND"));
//            System.out.println("   📧 Email: " + userData.getOrDefault("email", "NOT FOUND"));
//            System.out.println("   👤 First Name: " + userData.getOrDefault("firstName", "NOT FOUND"));
//            System.out.println("   👤 Last Name: " + userData.getOrDefault("lastName", "NOT FOUND"));
//            System.out.println("==========================================\n");
//
//            String username = userData.get("username");
//            String email = userData.get("email");
//            String firstName = userData.get("firstName");
//            String lastName = userData.get("lastName");
//
//            // Validate user data
//            if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
//                System.err.println("❌ Invalid SAML response - no user information found");
//                model.addAttribute("error", "SAML Authentication failed: No user information found in SAML response");
//                model.addAttribute("allParams", allParams);
//                return "sso-error";
//            }
//
//            // Process user and generate JWT
//            String appJwtToken = miniOrangeSsoService.processUserAfterSso(username, email, firstName, lastName);
//
//            // Store in session
//            session.setAttribute("jwt_token", appJwtToken);
//            session.setAttribute("username", username != null ? username : email);
//            session.setAttribute("authenticated_via", "saml");
//
//            System.out.println("✅ SAML authentication successful for: " + (username != null ? username : email));
//
//            // Redirect to success page
//            model.addAttribute("jwtToken", appJwtToken);
//            model.addAttribute("username", username != null ? username : email);
//            model.addAttribute("email", email);
//
//            return "home";
//
//        } catch (Exception e) {
//            System.err.println("❌ SAML authentication failed: " + e.getMessage());
//            e.printStackTrace();
//            model.addAttribute("error", "SAML authentication failed: " + e.getMessage());
//            model.addAttribute("allParams", allParams);
//            return "sso-error";
//        }
//    }
//
//    /**
//     * Generate SAML Authentication Request
//     */
//    private String generateSamlRequest(SsoConfig config) {
//        String entityId = config.getSamlEntityId();
//        String acsUrl = config.getSamlAcsUrl();
//
//        // Simple SAML Request XML
//        StringBuilder samlRequest = new StringBuilder();
//        samlRequest.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
//        samlRequest.append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
//        samlRequest.append("ID=\"_" + java.util.UUID.randomUUID().toString() + "\" ");
//        samlRequest.append("Version=\"2.0\" ");
//        samlRequest.append("IssueInstant=\"" + java.time.Instant.now().toString() + "\" ");
//        samlRequest.append("AssertionConsumerServiceURL=\"" + acsUrl + "\">");
//        samlRequest.append("<saml:Issuer>" + entityId + "</saml:Issuer>");
//        samlRequest.append("<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" />");
//        samlRequest.append("</samlp:AuthnRequest>");
//
//        return samlRequest.toString();
//    }
//
//    /**
//     * Parse SAML Response and extract user attributes
//     */
//    private Map<String, String> parseSamlResponse(String samlResponse) throws Exception {
//        Map<String, String> userData = new HashMap<>();
//
//        try {
//            // Decode Base64
//            byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
//            String decodedResponse = new String(decodedBytes);
//
//            System.out.println("🔓 Decoded SAML Response (first 500 chars): " +
//                    decodedResponse.substring(0, Math.min(500, decodedResponse.length())));
//
//            // Simple XML parsing (in production, use proper XML parser)
//            // Extract NameID (username)
//            if (decodedResponse.contains("<saml:NameID")) {
//                String nameId = extractXmlValue(decodedResponse, "<saml:NameID", "</saml:NameID>");
//                userData.put("username", nameId);
//                userData.put("email", nameId); // Often NameID is email
//            }
//
//            // Extract attributes
//            userData.put("firstName", extractAttribute(decodedResponse, "FirstName", "first_name", "givenName"));
//            userData.put("lastName", extractAttribute(decodedResponse, "LastName", "last_name", "familyName"));
//
//            String email = extractAttribute(decodedResponse, "Email", "email", "mail");
//            if (email != null && !email.isEmpty()) {
//                userData.put("email", email);
//            }
//
//        } catch (Exception e) {
//            System.err.println("Error parsing SAML response: " + e.getMessage());
//            throw e;
//        }
//
//        return userData;
//    }
//
//    /**
//     * Extract XML value between tags
//     */
//    private String extractXmlValue(String xml, String startTag, String endTag) {
//        try {
//            int start = xml.indexOf(startTag);
//            if (start == -1) return null;
//
//            start = xml.indexOf(">", start) + 1;
//            int end = xml.indexOf(endTag, start);
//
//            if (end == -1) return null;
//
//            return xml.substring(start, end).trim();
//        } catch (Exception e) {
//            return null;
//        }
//    }
//
//    /**
//     * Extract SAML attribute by multiple possible names
//     */
//    private String extractAttribute(String xml, String... attributeNames) {
//        for (String attrName : attributeNames) {
//            String pattern = "Name=\"" + attrName + "\"";
//            int attrPos = xml.indexOf(pattern);
//
//            if (attrPos != -1) {
//                int valueStart = xml.indexOf("<saml:AttributeValue", attrPos);
//                if (valueStart != -1) {
//                    valueStart = xml.indexOf(">", valueStart) + 1;
//                    int valueEnd = xml.indexOf("</saml:AttributeValue>", valueStart);
//                    if (valueEnd != -1) {
//                        return xml.substring(valueStart, valueEnd).trim();
//                    }
//                }
//            }
//        }
//        return null;
//    }
//}