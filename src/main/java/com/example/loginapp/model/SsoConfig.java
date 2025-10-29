package com.example.loginapp.model;

import jakarta.persistence.*;

@Entity
@Table(name = "sso_config")
public class SsoConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Boolean ssoEnabled = false;

    @Column
    private String ssoType; // JWT, OAUTH, SAML

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

    // SAML Configuration
    @Column(length = 2000)
    private String samlEntityId;

    @Column(length = 2000)
    private String samlSsoUrl;

    @Column(length = 2000)
    private String samlX509Certificate;

    @Column(length = 1000)
    private String samlCallbackUrl;

    @Column
    private String lastModifiedBy;

    @Column
    private java.time.LocalDateTime lastModifiedAt;

    public SsoConfig() {}

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Boolean getSsoEnabled() { return ssoEnabled; }
    public void setSsoEnabled(Boolean ssoEnabled) { this.ssoEnabled = ssoEnabled; }

    public String getSsoType() { return ssoType; }
    public void setSsoType(String ssoType) { this.ssoType = ssoType; }

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

    public String getSamlEntityId() { return samlEntityId; }
    public void setSamlEntityId(String samlEntityId) { this.samlEntityId = samlEntityId; }

    public String getSamlSsoUrl() { return samlSsoUrl; }
    public void setSamlSsoUrl(String samlSsoUrl) { this.samlSsoUrl = samlSsoUrl; }

    public String getSamlX509Certificate() { return samlX509Certificate; }
    public void setSamlX509Certificate(String samlX509Certificate) { this.samlX509Certificate = samlX509Certificate; }

    public String getSamlCallbackUrl() { return samlCallbackUrl; }
    public void setSamlCallbackUrl(String samlCallbackUrl) { this.samlCallbackUrl = samlCallbackUrl; }

    public String getLastModifiedBy() { return lastModifiedBy; }
    public void setLastModifiedBy(String lastModifiedBy) { this.lastModifiedBy = lastModifiedBy; }

    public java.time.LocalDateTime getLastModifiedAt() { return lastModifiedAt; }
    public void setLastModifiedAt(java.time.LocalDateTime lastModifiedAt) { this.lastModifiedAt = lastModifiedAt; }
}