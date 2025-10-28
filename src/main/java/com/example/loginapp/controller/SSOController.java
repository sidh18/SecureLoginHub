//package com.example.loginapp.controller;
//
//import com.example.loginapp.service.MiniOrangeSsoService;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import jakarta.servlet.http.HttpSession;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.*;
//
//import java.io.IOException;
//import java.util.Enumeration;
//import java.util.HashMap;
//import java.util.Map;
//
//@Controller
//@RequestMapping("/sso")
//public class SSOController {
//
//    @Autowired
//    private MiniOrangeSsoService miniOrangeSsoService;
//
//    /**
//     * Initiate SSO Login - Redirect to MiniOrange
//     */
//    @GetMapping("/login")
//    public void initiateSSO(HttpServletResponse response) throws IOException {
//        String ssoUrl = miniOrangeSsoService.getSsoLoginUrl();
//        System.out.println("🔐 Redirecting to MiniOrange SSO: " + ssoUrl);
//        response.sendRedirect(ssoUrl);
//    }
//
//    /**
//     * SSO Callback - Handle response from MiniOrange
//     * MiniOrange will send user data as request parameters or in POST body
//     */
//    @RequestMapping(value = "/callback", method = {RequestMethod.GET, RequestMethod.POST})
//    public String handleCallback(
//            HttpServletRequest request,
//            HttpSession session,
//            Model model) {
//
//        System.out.println("\n========== SSO CALLBACK RECEIVED ==========");
//
//        // Log all parameters received
//        Map<String, String> allParams = new HashMap<>();
//        Enumeration<String> paramNames = request.getParameterNames();
//
//        System.out.println("📦 All parameters received:");
//        while (paramNames.hasMoreElements()) {
//            String paramName = paramNames.nextElement();
//            String paramValue = request.getParameter(paramName);
//            allParams.put(paramName, paramValue);
//            System.out.println("  - " + paramName + " = " + paramValue);
//        }
//
//        // Try to extract user information from common parameter names
//        String username = extractParameter(request, "username", "user", "name", "sub", "preferred_username");
//        String email = extractParameter(request, "email", "mail", "emailAddress");
//        String firstName = extractParameter(request, "firstName", "given_name", "givenName");
//        String lastName = extractParameter(request, "lastName", "family_name", "familyName");
//        String status = extractParameter(request, "status", "success", "authenticated");
//        String token = extractParameter(request, "token", "jwt", "id_token", "access_token");
//
//        System.out.println("\n📋 Extracted information:");
//        System.out.println("  Username: " + username);
//        System.out.println("  Email: " + email);
//        System.out.println("  First Name: " + firstName);
//        System.out.println("  Last Name: " + lastName);
//        System.out.println("  Status: " + status);
//        System.out.println("  Token: " + (token != null ? "Present (length: " + token.length() + ")" : "Not found"));
//        System.out.println("==========================================\n");
//
//        // Check if we have a MiniOrange JWT token
//        if (token != null && !token.isEmpty()) {
//            System.out.println("🔑 MiniOrange JWT token received, processing...");
//            try {
//                // TODO: Validate MiniOrange JWT here if needed
//                // For now, we'll trust it and extract username from it
//
//                // Store MiniOrange token in session
//                session.setAttribute("miniorange_token", token);
//
//            } catch (Exception e) {
//                System.err.println("❌ Error processing MiniOrange JWT: " + e.getMessage());
//            }
//        }
//
//        // Validate if we have user information
//        if (!miniOrangeSsoService.isValidSsoResponse(username, email)) {
//            System.err.println("❌ Invalid SSO response - no user information");
//            model.addAttribute("error", "SSO Authentication failed: No user information received");
//            model.addAttribute("allParams", allParams);
//            return "sso-error";
//        }
//
//        try {
//            // Process user and generate our app's JWT token
//            String appJwtToken = miniOrangeSsoService.processUserAfterSso(username, email, firstName, lastName);
//
//            // Store JWT in session
//            session.setAttribute("jwt_token", appJwtToken);
//            session.setAttribute("username", username != null ? username : email);
//            session.setAttribute("authenticated_via", "sso");
//
//            System.out.println("✅ SSO authentication successful for: " + (username != null ? username : email));
//
//            // Redirect to success page
//            model.addAttribute("jwtToken", appJwtToken);
//            model.addAttribute("username", username != null ? username : email);
//            model.addAttribute("email", email);
//
//            return "sso-success";
//
//        } catch (Exception e) {
//            System.err.println("❌ SSO authentication failed: " + e.getMessage());
//            e.printStackTrace();
//            model.addAttribute("error", "SSO authentication failed: " + e.getMessage());
//            model.addAttribute("allParams", allParams);
//            return "sso-error";
//        }
//    }
//
//    /**
//     * Helper method to extract parameter from multiple possible names
//     */
//    private String extractParameter(HttpServletRequest request, String... paramNames) {
//        for (String paramName : paramNames) {
//            String value = request.getParameter(paramName);
//            if (value != null && !value.isEmpty()) {
//                return value;
//            }
//        }
//        return null;
//    }
//
//    /**
//     * SSO Success page
//     */
//    @GetMapping("/success")
//    public String ssoSuccess(HttpSession session, Model model) {
//        String jwtToken = (String) session.getAttribute("jwt_token");
//        String username = (String) session.getAttribute("username");
//
//        if (jwtToken != null) {
//            model.addAttribute("jwtToken", jwtToken);
//        }
//        if (username != null) {
//            model.addAttribute("username", username);
//        }
//
//        return "sso-success";
//    }
//
//    /**
//     * SSO Logout
//     */
//    @GetMapping("/logout")
//    public void ssoLogout(HttpSession session, HttpServletResponse response) throws IOException {
//        // Clear session
//        session.invalidate();
//
//        // Redirect to MiniOrange logout
//        String logoutUrl = miniOrangeSsoService.getSsoLogoutUrl();
//        System.out.println("🚪 Logging out, redirecting to: " + logoutUrl);
//        response.sendRedirect(logoutUrl);
//    }
//}