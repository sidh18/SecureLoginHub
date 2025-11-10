package com.example.loginapp.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.Set;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import java.util.Set; // Make sure this is imported
import com.fasterxml.jackson.annotation.JsonManagedReference;


@Entity
@Table(name = "organizations")
public class Organization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false, unique = true)
    private String subdomain;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    // --- Relationships ---

    @OneToMany(mappedBy = "organization", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference  // Avoid infinite loops when serializing
    private Set<user> users;

    @OneToMany(mappedBy = "organization", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonIgnore // Avoid infinite loops when serializing
    private Set<SsoConfig> ssoConfigs;

    @OneToMany(mappedBy = "organization", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference("organization-bugs") // Use the unique name
    private Set<BugReport> bugReports;

    // --- Lifecycle Callbacks ---

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    // --- Getters and Setters ---

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Set<user> getUsers() {
        return users;
    }

    public void setUsers(Set<user> users) {
        this.users = users;
    }

    public Set<SsoConfig> getSsoConfigs() {
        return ssoConfigs;
    }

    public void setSsoConfigs(Set<SsoConfig> ssoConfigs) {
        this.ssoConfigs = ssoConfigs;
    }
}
