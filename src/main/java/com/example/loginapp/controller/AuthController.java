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
    @PostMapping("/api/auth/signup")
    @ResponseBody
    public ResponseEntity<?> registerUser(@RequestBody Map<String, String> request) {

        // --- TENANT-AWARE ---
        Long organizationId = TenantContext.getCurrentOrganizationId();

        // Get common user details from the request
        String username = request.get("username");
        String password = request.get("password");
        String email = request.get("email");
        String firstName = request.get("firstName");
        String lastName = request.get("lastName");

        try {
            if (organizationId == null) {
                // ===============================================
                //  PATH 1: SUPERADMIN DOMAIN (Create Product Admin + Org)
                // ===============================================

                // 1. Get extra fields required for a new organization
                String organizationName = request.get("organizationName");
                String subdomain = request.get("subdomain");

                // 2. Validate input
                if (organizationName == null || organizationName.isBlank() || subdomain == null || subdomain.isBlank()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Organization name and subdomain are required."));
                }
                if (userRepository.findByUsernameAndOrganizationIdIsNull(username).isPresent()) {
                    // This check is for other superadmins, which you might not allow.
                    // A better check would be for username/email uniqueness globally.
                    return ResponseEntity.badRequest().body(Map.of("error", "Username already exists."));
                }
                if (organizationRepository.findBySubdomain(subdomain).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "This subdomain is already taken."));
                }
                if (userRepository.findByEmail(email).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "This email is already in use."));
                }


                // 3. Create the new Organization
                Organization newOrg = new Organization();
                newOrg.setName(organizationName);
                newOrg.setSubdomain(subdomain);
                Organization savedOrg = organizationRepository.save(newOrg);

                // 4. Create the new "Product Admin" user
                user adminUser = new user();
                adminUser.setUsername(username);
                adminUser.setPassword(passwordEncoder.encode(password));
                adminUser.setEmail(email);
                adminUser.setFirstName(firstName);
                adminUser.setLastName(lastName);
                adminUser.setRole("ROLE_ADMIN"); // Set role to ADMIN
                adminUser.setOrganization(savedOrg); // Link to the new organization

                userRepository.save(adminUser);

                return ResponseEntity.ok(Map.of("message", "Organization and admin user created successfully!"));

            } else {
                // ===============================================
                //  PATH 2: TENANT DOMAIN (Create End User)
                // ===============================================

                // 1. Validate input
                if (userRepository.findByUsernameAndOrganizationId(username, organizationId).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Username already exists for this organization."));
                }
                if (userRepository.findByEmail(email).isPresent()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "This email is already in use."));
                }

                // 2. Find the existing organization
                Organization tenantOrg = organizationRepository.findById(organizationId)
                        .orElseThrow(() -> new Exception("Invalid organization ID. This should not happen."));

                // 3. Create the new "End User"
                user newUser = new user();
                newUser.setUsername(username);
                newUser.setPassword(passwordEncoder.encode(password));
                newUser.setEmail(email);
                newUser.setFirstName(firstName);
                newUser.setLastName(lastName);
                newUser.setRole("ROLE_USER"); // Set role to USER
                newUser.setOrganization(tenantOrg); // Link to the *existing* organization

                user savedUser = userRepository.save(newUser);
                return ResponseEntity.ok(savedUser); // Return the new user object
            }
        } catch (Exception e) {
            // Catch any other errors (e.g., database constraint violations)
            return ResponseEntity.badRequest().body(Map.of("error", "An error occurred: " + e.getMessage()));
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

    @GetMapping("/signup")
    public String registerPage() {
        return "signup"; // Thymeleaf template name (e.g., register.html)
    }
}
