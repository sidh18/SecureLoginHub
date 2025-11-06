package com.example.loginapp.controller;

import com.example.loginapp.config.JwtUtil;
import com.example.loginapp.config.TenantContext; // Import TenantContext
import com.example.loginapp.model.Organization;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.repository.UserRepository;
import com.example.loginapp.security.CustomUserDetails;
import com.example.loginapp.service.AdminService;
import com.example.loginapp.model.user;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;
import java.util.Optional;
import java.util.List;

@Controller
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AdminService adminService; // Use this to create users

    @Autowired
    private OrganizationRepository organizationRepository; // To find the org

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Handles the standard username/password login.
     * This endpoint is called by the login form's JavaScript.
     */
    @PostMapping("/api/auth/login")
    @ResponseBody
    public ResponseEntity<Map<String, String>> createAuthenticationToken(@RequestBody Map<String, String> request) throws Exception {

        String username = request.get("username");
        String password = request.get("password");

        // --- TENANT-AWARE ---
        // We use the TenantContext to build a special authentication token
        // that tells our CustomUserDetailsService which tenant to check.
        Long organizationId = TenantContext.getCurrentOrganizationId();

        // We can't use the simple UsernamePasswordAuthenticationToken anymore.
        // We need to find the user first, respecting the tenant,
        // then manually authenticate.

        Optional<user> userOptional;
        if (organizationId == null) {
            // This is the 'superadmin.localhost' domain
            userOptional = userRepository.findByUsernameAndOrganizationIdIsNull(username);
        } else {
            // This is a tenant domain like 'acme.localhost'
            userOptional = userRepository.findByUsernameAndOrganizationId(username, organizationId);
        }

        if (userOptional.isEmpty()) {
            throw new Exception("Incorrect username or password");
        }

        user user = userOptional.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new Exception("Incorrect username or password");
        }

        // --- Manually create the Authentication object ---
        CustomUserDetails userDetails = new CustomUserDetails(
                user.getUsername(),
                user.getPassword(),
                List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority(user.getRole())),
                organizationId
        );

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate the token
        final String token = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(Map.of("token", token, "role", userDetails.getMainRole()));
    }

    /**
     * Handles new user registration. (Tenant-Aware)
     */
    @PostMapping("/api/auth/register")
    @ResponseBody
    public ResponseEntity<?> registerUser(@RequestBody Map<String, String> request) {

        // --- TENANT-AWARE ---
        Long organizationId = TenantContext.getCurrentOrganizationId();

        if (organizationId == null) {
            // Superadmin domain. Registration is disabled.
            return ResponseEntity.badRequest().body(Map.of("error", "Registration is not allowed on this domain."));
        }

        // We can proceed with registration for the current tenant.
        try {
            String username = request.get("username");
            String password = request.get("password");
            String email = request.get("email");
            String firstName = request.get("firstName");
            String lastName = request.get("lastName");

            // Create the user using the AdminService, which assigns the org ID
            user newUser = adminService.createUser(
                    username,
                    password,
                    email,
                    firstName,
                    lastName,
                    "ROLE_USER", // New registered users are always ROLE_USER
                    organizationId
            );

            return ResponseEntity.ok(Map.of("message", "User registered successfully", "userId", newUser.getId()));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // --- Page Views ---

    @GetMapping("/")
    public String loginPage() {
        return "login"; // Thymeleaf template name (e.g., login.html)
    }

    @GetMapping("/home")
    public String homePage(Model model, Authentication authentication, HttpSession session) {

        String username = null;
        String jwtToken = null;

        // --- FIX: Get user info from EITHER Spring Security or the Session ---

        // Case 1: User logged in via standard form login
        if (authentication != null && authentication.getPrincipal() instanceof CustomUserDetails) {
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            username = userDetails.getUsername();

            // Generate a JWT for them to use
            jwtToken = jwtUtil.generateToken(userDetails);

            // Also, store it in the session for consistency
            session.setAttribute("jwt_token", jwtToken);
            session.setAttribute("username", username);

        }
        // Case 2: User logged in via SSO (controllers put details in session)
        else if (session.getAttribute("username") != null) {
            username = (String) session.getAttribute("username");
            jwtToken = (String) session.getAttribute("jwt_token");
        }

        // If we still have no user, something is wrong, but security should catch this.
        // We'll add the attributes (even if null) so Thymeleaf can handle it.

        model.addAttribute("username", username);
        model.addAttribute("jwtToken", jwtToken);

        return "home"; // Thymeleaf template name (e.g., home.html)
    }
//    public String homePage() {
//        return "home"; // Thymeleaf template name (e.g., home.html)
//    }

    @GetMapping("/register")
    public String registerPage() {
        return "register"; // Thymeleaf template name (e.g., register.html)
    }
}
