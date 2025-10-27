package com.example.loginapp.controller;

import com.example.loginapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String login() {
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
        return "home";
    }
}