package com.example.loginapp.service;

import com.example.loginapp.model.Organization;
import com.example.loginapp.model.user;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class AdminService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Gets all users for a specific organization (for Tenant Admins).
     */
    public List<user> getAllUsersForOrganization(Long organizationId) {
        if (organizationId == null) {
            // This shouldn't be called for a superadmin
            throw new IllegalArgumentException("Organization ID cannot be null");
        }
        return userRepository.findByOrganizationId(organizationId);
    }

    /**
     * Gets ALL users from ALL organizations (for Superadmins).
     */
    public List<user> getAllUsersForSuperAdmin() {
        return userRepository.findAll();
    }

    /**
     * --- NEW ---
     * Gets a single user by ID, with tenant security check.
     */
    public user getUserById(Long userId, Long adminOrgId) throws SecurityException {
        user user = userRepository.findById(userId)
                .orElse(null);

        if (user == null) {
            return null;
        }

        // --- SECURITY CHECK ---
        // If adminOrgId is not null, this is a Tenant Admin.
        // Check if the user they are fetching belongs to their org.
        if (adminOrgId != null) {
            if (user.getOrganization() == null || !user.getOrganization().getId().equals(adminOrgId)) {
                throw new SecurityException("Access Denied: User not found in your organization.");
            }
        }
        // If adminOrgId is null, it's a Superadmin, who can fetch anyone.
        return user;
    }


    /**
     * Creates a new user. This is now tenant-aware.
     * The organizationId is passed in from the controller.
     */
    public user createUser(String username, String password, String email, String firstName, String lastName, String role, Long organizationId) throws Exception {

        // Check if user exists *within this tenant*
        Optional<user> existingUser;
        if (organizationId == null) {
            // Superadmin check (no org)
            existingUser = userRepository.findByUsernameAndOrganizationIdIsNull(username);
        } else {
            // Tenant check
            existingUser = userRepository.findByUsernameAndOrganizationId(username, organizationId);
        }

        if (existingUser.isPresent()) {
            throw new Exception("Username '" + username + "' already exists for this organization.");
        }

        user newUser = new user();
        newUser.setUsername(username);
        newUser.setPassword(passwordEncoder.encode(password));
        newUser.setEmail(email);
        newUser.setFirstName(firstName);
        newUser.setLastName(lastName);
        newUser.setRole(role); // e.g., "ROLE_ADMIN" or "ROLE_USER"
        newUser.setActive(true);
        newUser.setCreatedVia("REGULAR");

        // Set the organization for the new user
        if (organizationId != null) {
            Organization org = organizationRepository.findById(organizationId)
                    .orElseThrow(() -> new Exception("Organization not found"));
            newUser.setOrganization(org);
        }
        // If organizationId is null, the user is created with no organization
        // (This is how a Superadmin can create another Superadmin)

        return userRepository.save(newUser);
    }

    /**
     * Updates a user. Also tenant-aware.
     * --- MODIFIED: Signature changed to accept 9 arguments ---
     * The requesting admin can only update users in their own org, unless they are Superadmin.
     */
    public user updateUser(Long userId, String username, String email, String firstName, String lastName, String role,
                           Boolean active, Long adminOrgId, boolean isSuperAdmin) throws Exception {

        user userToUpdate = userRepository.findById(userId)
                .orElseThrow(() -> new Exception("User not found"));

        // --- SECURITY CHECK ---
        // A Tenant Admin (non-null orgId) cannot edit a user in another org.
        if (!isSuperAdmin) { // This is a Tenant Admin
            if (adminOrgId == null) {
                throw new Exception("Access Denied: Invalid admin session.");
            }
            if (userToUpdate.getOrganization() == null || !userToUpdate.getOrganization().getId().equals(adminOrgId)) {
                throw new Exception("Access Denied: You cannot edit users outside your organization.");
            }
        }
        // A Superadmin (isSuperAdmin = true) can edit anyone.

        // Update fields
        userToUpdate.setUsername(username);
        userToUpdate.setEmail(email);
        userToUpdate.setFirstName(firstName);
        userToUpdate.setLastName(lastName);
        userToUpdate.setRole(role);
        userToUpdate.setActive(active);

        return userRepository.save(userToUpdate);
    }

    /**
     * Deletes a user. Also tenant-aware.
     * --- MODIFIED: Signature changed to accept 3 arguments ---
     */
    public boolean deleteUser(Long userId, Long adminOrgId, boolean isSuperAdmin) throws Exception {
        user userToDelete = userRepository.findById(userId)
                .orElseThrow(() -> new Exception("User not found"));

        // --- SECURITY CHECK ---
        if (!isSuperAdmin) { // This is a Tenant Admin
            if (adminOrgId == null) {
                throw new Exception("Access Denied: Invalid admin session.");
            }
            if (userToDelete.getOrganization() == null || !userToDelete.getOrganization().getId().equals(adminOrgId)) {
                throw new Exception("Access Denied: You cannot delete users outside your organization.");
            }
        }
        // Superadmin (isSuperAdmin = true) can delete anyone.

        userRepository.delete(userToDelete);
        return true;
    }

    // --- NEW SUPERADMIN METHODS ---

    /**
     * --- RENAMED --- (Was createOrganization)
     * Creates a new Organization and its first Admin user.
     * This is called by the old DataInitializer or a future "wizard".
     */
    public Organization createOrganizationAndAdmin(String orgName, String subdomain, String adminUsername, String adminPassword, String adminEmail) throws Exception {

        // 1. Check if subdomain is available
        if (organizationRepository.findBySubdomain(subdomain).isPresent()) {
            throw new Exception("Subdomain '" + subdomain + "' is already taken.");
        }

        // 2. Create the Organization
        Organization newOrg = new Organization();
        newOrg.setName(orgName);
        newOrg.setSubdomain(subdomain);
        Organization savedOrg = organizationRepository.save(newOrg);

        // 3. Create the Tenant Admin user for this organization
        try {
            createUser(
                    adminUsername,
                    adminPassword,
                    adminEmail,
                    "Admin", // First name
                    "User",  // Last name
                    "ROLE_ADMIN", // This is now a Tenant Admin
                    savedOrg.getId() // Link to the new org
            );
        } catch (Exception e) {
            // If creating the user fails, roll back the org creation
            // (In a real app, you'd use @Transactional for this)
            organizationRepository.delete(savedOrg);
            throw new Exception("Failed to create admin user: " + e.getMessage());
        }

        return savedOrg;
    }

    /**
     * --- NEW ---
     * Creates just the organization.
     * This is called by the SuperadminController.
     */
    public Organization createOrganization(String orgName, String subdomain) throws Exception {
        // 1. Check if subdomain is available
        if (organizationRepository.findBySubdomain(subdomain).isPresent()) {
            throw new Exception("Subdomain '" + subdomain + "' is already taken.");
        }
        if ("superadmin".equals(subdomain)) {
            throw new Exception("Subdomain 'superadmin' is reserved.");
        }

        // 2. Create the Organization
        Organization newOrg = new Organization();
        newOrg.setName(orgName);
        newOrg.setSubdomain(subdomain);
        return organizationRepository.save(newOrg);
    }



    /**
     * Gets all organizations (for Superadmin).
     */
    public List<Organization> getAllOrganizations() {
        return organizationRepository.findAll();
    }

    /**
     * --- NEW ---
     * Gets global stats for the Superadmin dashboard.
     */
    public Map<String, Object> getGlobalStats() {
        long totalUsers = userRepository.count();
        long totalOrgs = organizationRepository.count();
        // We subtract 1 from orgs to not count the 'superadmin' dummy org
        return Map.of(
                "totalUsers", totalUsers,
                "totalOrganizations", totalOrgs > 0 ? totalOrgs - 1 : 0
                // Add more stats as needed
        );
    }

    /**
     * --- NEW ---
     * Changes a user's organization (Superadmin only).
     */
    public user changeUserOrganization(Long userId, Long newOrganizationId) throws Exception {
        user userToUpdate = userRepository.findById(userId)
                .orElseThrow(() -> new Exception("User not found"));

        Organization newOrg = organizationRepository.findById(newOrganizationId)
                .orElseThrow(() -> new Exception("Organization not found"));

        // You might add checks here, e.g., don't allow changing a Superadmin's org
        if ("ROLE_SUPER_ADMIN".equals(userToUpdate.getRole())) {
            throw new Exception("Cannot assign a Superadmin to an organization.");
        }

        userToUpdate.setOrganization(newOrg);
        return userRepository.save(userToUpdate);
    }
}

