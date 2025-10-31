package com.example.loginapp.controller;

import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.service.UserService;
import com.example.loginapp.service.SsoConfigService;
import com.example.loginapp.config.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private SsoConfigService ssoConfigService;

    @GetMapping("/")
    public String login(Model model) {
        // Get all enabled SSO configurations
        List<SsoConfig> ssoConfigs = ssoConfigService.getEnabledSsoConfigs();
        boolean ssoEnabled = !ssoConfigs.isEmpty();

        model.addAttribute("ssoEnabled", ssoEnabled);
        model.addAttribute("ssoConfigs", ssoConfigs);

        return "login";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           Model model) {
        try {
            userService.registerUser(username, password);
            model.addAttribute("message", "Registration successful! Please login.");
            return "login";
        } catch (Exception e) {
            model.addAttribute("error", "Username already exists!");
            return "signup";
        }
    }

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        String username = authentication.getName();
        model.addAttribute("username", username);

        // Generate JWT token for the logged-in user
        String jwtToken = jwtUtil.generateToken(username);
        model.addAttribute("jwtToken", jwtToken);

        // Check if user is admin
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") ||
                        a.getAuthority().equals("ADMIN"));
        model.addAttribute("isAdmin", isAdmin);

        return "home";
    }
}