package com.example.loginapp.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "bug_reports")
public class BugReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String description;

    @Column(nullable = false)
    private String status; // "OPEN", "IN_PROGRESS", "CLOSED"

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    // --- Relationships ---

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = false)
    @JsonBackReference("organization-bugs") // Use a unique name
    private Organization organization;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonBackReference("user-bugs") // Use a unique name
    private user reportedBy;

    // --- Lifecycle Callbacks ---

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
        if (this.status == null) {
            this.status = "OPEN";
        }
    }

    // --- Getters and Setters ---

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }

    public user getReportedBy() {
        return reportedBy;
    }

    public void setReportedBy(user reportedBy) {
        this.reportedBy = reportedBy;
    }

    // --- Helper Getters for JSON Serialization ---

    @Transient
    public String getOrganizationName() {
        return (organization != null) ? organization.getName() : null;
    }

    @Transient
    public String getReportedByUsername() {
        return (reportedBy != null) ? reportedBy.getUsername() : null;
    }
}