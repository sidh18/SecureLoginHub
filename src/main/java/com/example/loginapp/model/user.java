package com.example.loginapp.model;

import com.fasterxml.jackson.annotation.JsonBackReference; // <-- IMPORT THIS
import java.util.Set; // <-- IMPORT THIS
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "users")
public class user {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true) // Email should also be unique
    private String email    ;

    @Column
    private String firstName;

    @Column
    private String lastName;

    @Column(nullable = false)
    private String role; // "ROLE_USER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN"

    // --- THIS IS THE FIX ---
    // Changed from 'boolean' to 'Boolean'.
    // 'Boolean' is a wrapper class that can be null.
    // 'boolean' is a primitive that cannot be null.
    // We also set a default value for new entities.
    @Column
    private Boolean active = true;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column
    private String createdVia; // "REGULAR" or "SSO"

    // --- MULTI-TENANCY ---
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = true)
    @JsonBackReference // <-- ADD THIS ANNOTATION
    private Organization organization;

    @OneToMany(mappedBy = "reportedBy", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference("user-bugs") // Use the unique name
    private Set<BugReport> bugReports;

    // --- Lifecycle Callbacks ---

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
        if (this.createdVia == null) {
            this.createdVia = "REGULAR";
        }
        if (this.role == null) {
            this.role = "ROLE_USER";
        }
        // Ensure active is set on creation if it's somehow null
        if (this.active == null) {
            this.active = true;
        }
    }

    // --- Constructors ---

    public user() {
        // Default constructor
    }

    public user(String username, String password) {
        this.username = username;
        this.password = password;
    }


    // --- All Getters and Setters ---

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    // --- UPDATED GETTER/SETTER ---
    // Now returns and accepts the Boolean wrapper class.
    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedVia() {
        return createdVia;
    }

    public void setCreatedVia(String createdVia) {
        this.createdVia = createdVia;
    }

    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }

    // --- HELPER GETTERS ---

    /**
     * --- NEW METHOD ---
     * This adds an "organizationName" field to the JSON output,
     * which the superadmin-dashboard.html is expecting.
     *
     * @return The name of the organization, or null.
     */
    @Transient // Don't persist this to the DB
    public String getOrganizationName() {
        if (organization != null) {
            return organization.getName();
        }
        return null;
    }
}


