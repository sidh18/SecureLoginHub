package com.example.loginapp.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

import java.time.Instant;
import java.time.LocalDateTime;

@Entity
@Table(name = "sso_config")
public class SsoConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name; // Unique name for this SSO config

    @Column(nullable = false)
    private String ssoType; // JWT, OAUTH, SAML

    // --- FIX 1: RESTORE THIS FIELD ---
    // This field must match your database column "sso_enabled"
    @Column(name = "sso_enabled", nullable = false)
    private boolean ssoEnabled = false; // Default to false

    @Column(nullable = false)
    private Boolean enabled = false;

    @Column
    private Integer priority = 0; // Display order on login page

    // JWT Configuration
    @Column(length = 1000)
    private String jwtClientId;

    @Column(length = 1000)
    private String jwtSsoUrl;

    @Column(length = 1000)
    private String jwtCallbackUrl;

    @Column(length = 1000)
    private String jwtLogoutUrl;

    // OAuth Configuration
    @Column(length = 1000)
    private String oauthClientId;

    @Column(length = 1000)
    private String oauthClientSecret;

    @Column(length = 1000)
    private String oauthAuthorizationUrl;

    @Column(length = 1000)
    private String oauthTokenUrl;

    @Column(length = 1000)
    private String oauthCallbackUrl;

    @Column(length = 1000)
    private String oauthUserInfoUrl;

    // SAML Configuration
    @Column(length = 2000)
    private String samlEntityId; // SP Entity ID

    @Column(length = 2000)
    private String samlIdpEntityId; // IDP Entity ID

    @Column(length = 2000)
    private String samlSsoUrl; // IDP SSO URL

    @Column(length = 5000)
    private String samlX509Certificate; // IDP Certificate

    @Column(length = 1000)
    private String samlAcsUrl; // Assertion Consumer Service URL

    @Column(length = 5000)
    private String samlSpMetadata; // SP Metadata XML

    @Column(length = 5000)
    private String samlIdpMetadata; // IDP Metadata XML

    @Column
    private String lastModifiedBy;

    // --- FIX 1: Change type from LocalDateTime to Instant ---
    @Column
    private Instant lastModifiedAt;

    // --- MULTI-TENANCY ---
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = true)
    // --- FIX 2: Add JsonBackReference to prevent JSON infinite loops ---
    @JsonBackReference
    private Organization organization;

    // --- Lifecycle Callbacks ---

    @PreUpdate
    @PrePersist
    protected void onUpdate() {
        // --- FIX 3: Use Instant.now() ---
        lastModifiedAt = Instant.now();
    }



    public SsoConfig() {}

    // Getters and Setters

    // --- FIX 2: RESTORE THE GETTER ---
    public boolean isSsoEnabled() {
        return ssoEnabled;
    }

    // --- FIX 3: RESTORE THE SETTER ---
    public void setSsoEnabled(boolean ssoEnabled) {
        this.ssoEnabled = ssoEnabled;
        this.enabled = ssoEnabled; // Keep them in sync
    }

    public boolean isEnabled() {
        return enabled;
    }

    // --- FIX 4: UPDATE THIS SETTER TO SYNC BOTH FIELDS ---
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        this.ssoEnabled = enabled; // Keep them in sync
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getSsoType() { return ssoType; }
    public void setSsoType(String ssoType) { this.ssoType = ssoType; }

    public Boolean getEnabled() { return enabled; }
    // --- FIX 5: UPDATE THIS SETTER TO SYNC BOTH FIELDS ---
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled != null ? enabled : false;
        this.ssoEnabled = this.enabled; // Keep them in sync
    }

    public Integer getPriority() { return priority; }
    public void setPriority(Integer priority) { this.priority = priority; }

    public String getJwtClientId() { return jwtClientId; }
    public void setJwtClientId(String jwtClientId) { this.jwtClientId = jwtClientId; }

    public String getJwtSsoUrl() { return jwtSsoUrl; }
    public void setJwtSsoUrl(String jwtSsoUrl) { this.jwtSsoUrl = jwtSsoUrl; }

    public String getJwtCallbackUrl() { return jwtCallbackUrl; }
    public void setJwtCallbackUrl(String jwtCallbackUrl) { this.jwtCallbackUrl = jwtCallbackUrl; }

    public String getJwtLogoutUrl() { return jwtLogoutUrl; }
    public void setJwtLogoutUrl(String jwtLogoutUrl) { this.jwtLogoutUrl = jwtLogoutUrl; }

    public String getOauthClientId() { return oauthClientId; }
    public void setOauthClientId(String oauthClientId) { this.oauthClientId = oauthClientId; }

    public String getOauthClientSecret() { return oauthClientSecret; }
    public void setOauthClientSecret(String oauthClientSecret) { this.oauthClientSecret = oauthClientSecret; }

    public String getOauthAuthorizationUrl() { return oauthAuthorizationUrl; }
    public void setOauthAuthorizationUrl(String oauthAuthorizationUrl) { this.oauthAuthorizationUrl = oauthAuthorizationUrl; }

    public String getOauthTokenUrl() { return oauthTokenUrl; }
    public void setOauthTokenUrl(String oauthTokenUrl) { this.oauthTokenUrl = oauthTokenUrl; }

    public String getOauthCallbackUrl() { return oauthCallbackUrl; }
    public void setOauthCallbackUrl(String oauthCallbackUrl) { this.oauthCallbackUrl = oauthCallbackUrl; }

    public String getOauthUserInfoUrl() { return oauthUserInfoUrl; }
    public void setOauthUserInfoUrl(String oauthUserInfoUrl) { this.oauthUserInfoUrl = oauthUserInfoUrl; }

    public String getSamlEntityId() { return samlEntityId; }
    public void setSamlEntityId(String samlEntityId) { this.samlEntityId = samlEntityId; }

    public String getSamlIdpEntityId() { return samlIdpEntityId; }
    public void setSamlIdpEntityId(String samlIdpEntityId) { this.samlIdpEntityId = samlIdpEntityId; }

    public String getSamlSsoUrl() { return samlSsoUrl; }
    public void setSamlSsoUrl(String samlSsoUrl) { this.samlSsoUrl = samlSsoUrl; }

    public String getSamlX509Certificate() { return samlX509Certificate; }
    public void setSamlX509Certificate(String samlX509Certificate) { this.samlX509Certificate = samlX509Certificate; }

    public String getSamlAcsUrl() { return samlAcsUrl; }
    public void setSamlAcsUrl(String samlAcsUrl) { this.samlAcsUrl = samlAcsUrl; }

    public String getSamlSpMetadata() { return samlSpMetadata; }
    public void setSamlSpMetadata(String samlSpMetadata) { this.samlSpMetadata = samlSpMetadata; }

    public String getSamlIdpMetadata() { return samlIdpMetadata; }
    public void setSamlIdpMetadata(String samlIdpMetadata) { this.samlIdpMetadata = samlIdpMetadata; }

    public String getLastModifiedBy() { return lastModifiedBy; }
    public void setLastModifiedBy(String lastModifiedBy) { this.lastModifiedBy = lastModifiedBy; }

    // --- FIX 4: Update Getter and Setter to use Instant ---
    public Instant getLastModifiedAt() { return lastModifiedAt; }
    public void setLastModifiedAt(Instant lastModifiedAt) { this.lastModifiedAt = lastModifiedAt; }

    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }

    // --- FIX 5: Add helper for JSON serialization, just like in user.java ---
    /**
     * This adds an "organizationName" field to the JSON output,
     * which the superadmin-dashboard.html is expecting.
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

