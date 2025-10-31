package com.example.loginapp.service;

import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.repository.SsoConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class SsoConfigService {

    @Autowired
    private SsoConfigRepository ssoConfigRepository;

    @Autowired
    private SamlMetadataService samlMetadataService;

    /**
     * Get all enabled SSO configurations
     */
    public List<SsoConfig> getEnabledSsoConfigs() {
        return ssoConfigRepository.findByEnabledTrueOrderByPriorityAsc();
    }

    /**
     * Check if any SSO is enabled
     */
    public boolean isAnySsoEnabled() {
        return !getEnabledSsoConfigs().isEmpty();
    }

    /**
     * Get specific SSO config by ID
     */
    public SsoConfig getSsoConfigById(Long id) {
        return ssoConfigRepository.findById(id).orElse(null);
    }

    /**
     * Get all SSO configurations
     */
    public List<SsoConfig> getAllSsoConfigs() {
        return ssoConfigRepository.findAll();
    }

    /**
     * Toggle SSO configuration
     */
    public SsoConfig toggleSso(Long id, boolean enabled, String modifiedBy) {
        SsoConfig config = ssoConfigRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("SSO Config not found"));

        config.setEnabled(enabled); // this also sets ssoEnabled
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());

        return ssoConfigRepository.save(config);
    }

    /**
     * Save JWT configuration
     */
    public SsoConfig saveJwtConfig(String name, String clientId, String ssoUrl,
                                   String callbackUrl, String logoutUrl,
                                   Integer priority, String modifiedBy) {
        SsoConfig config = new SsoConfig();
        config.setName(name);
        config.setSsoType("JWT");
        config.setEnabled(true);
        config.setPriority(priority != null ? priority : 0);
        config.setJwtClientId(clientId);
        config.setJwtSsoUrl(ssoUrl);
        config.setJwtCallbackUrl(callbackUrl);
        config.setJwtLogoutUrl(logoutUrl);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    /**
     * Update JWT configuration
     */
    public SsoConfig updateJwtConfig(Long id, String name, String clientId, String ssoUrl,
                                     String callbackUrl, String logoutUrl,
                                     Integer priority, String modifiedBy) {
        SsoConfig config = ssoConfigRepository.findById(id).orElse(null);
        if (config != null) {
            if (name != null) config.setName(name);
            if (clientId != null) config.setJwtClientId(clientId);
            if (ssoUrl != null) config.setJwtSsoUrl(ssoUrl);
            if (callbackUrl != null) config.setJwtCallbackUrl(callbackUrl);
            if (logoutUrl != null) config.setJwtLogoutUrl(logoutUrl);
            if (priority != null) config.setPriority(priority);
            config.setLastModifiedBy(modifiedBy);
            config.setLastModifiedAt(LocalDateTime.now());
            return ssoConfigRepository.save(config);
        }
        return null;
    }

    /**
     * Save OAuth configuration
     */
    public SsoConfig saveOAuthConfig(String name, String clientId, String clientSecret,
                                     String authUrl, String tokenUrl, String callbackUrl,
                                     String userInfoUrl, Integer priority, String modifiedBy) {
        SsoConfig config = new SsoConfig();
        config.setName(name);
        config.setSsoType("OAUTH");
        config.setEnabled(true);
        config.setPriority(priority != null ? priority : 0);
        config.setOauthClientId(clientId);
        config.setOauthClientSecret(clientSecret);
        config.setOauthAuthorizationUrl(authUrl);
        config.setOauthTokenUrl(tokenUrl);
        config.setOauthCallbackUrl(callbackUrl);
        config.setOauthUserInfoUrl(userInfoUrl);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    /**
     * Update OAuth configuration
     */
    public SsoConfig updateOAuthConfig(Long id, String name, String clientId, String clientSecret,
                                       String authUrl, String tokenUrl, String callbackUrl,
                                       String userInfoUrl, Integer priority, String modifiedBy) {
        SsoConfig config = ssoConfigRepository.findById(id).orElse(null);
        if (config != null) {
            if (name != null) config.setName(name);
            if (clientId != null) config.setOauthClientId(clientId);
            if (clientSecret != null) config.setOauthClientSecret(clientSecret);
            if (authUrl != null) config.setOauthAuthorizationUrl(authUrl);
            if (tokenUrl != null) config.setOauthTokenUrl(tokenUrl);
            if (callbackUrl != null) config.setOauthCallbackUrl(callbackUrl);
            if (userInfoUrl != null) config.setOauthUserInfoUrl(userInfoUrl);
            if (priority != null) config.setPriority(priority);
            config.setLastModifiedBy(modifiedBy);
            config.setLastModifiedAt(LocalDateTime.now());
            return ssoConfigRepository.save(config);
        }
        return null;
    }

    /**
     * Save SAML configuration
     */
    public SsoConfig saveSamlConfig(String name, String entityId, String idpEntityId,
                                    String ssoUrl, String certificate, String acsUrl,
                                    Integer priority, String modifiedBy) {
        SsoConfig config = new SsoConfig();
        config.setName(name);
        config.setSsoType("SAML");
        config.setEnabled(true);
        config.setPriority(priority != null ? priority : 0);
        config.setSamlEntityId(entityId);
        config.setSamlIdpEntityId(idpEntityId);
        config.setSamlSsoUrl(ssoUrl);
        config.setSamlX509Certificate(certificate);
        config.setSamlAcsUrl(acsUrl);

        // Generate SP Metadata
        String spMetadata = samlMetadataService.generateSpMetadata(entityId, acsUrl);
        config.setSamlSpMetadata(spMetadata);

        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    /**
     * Update SAML configuration
     */
    public SsoConfig updateSamlConfig(Long id, String name, String entityId, String idpEntityId,
                                      String ssoUrl, String certificate, String acsUrl,
                                      Integer priority, String modifiedBy) {
        SsoConfig config = ssoConfigRepository.findById(id).orElse(null);
        if (config != null) {
            if (name != null) config.setName(name);
            if (entityId != null) config.setSamlEntityId(entityId);
            if (idpEntityId != null) config.setSamlIdpEntityId(idpEntityId);
            if (ssoUrl != null) config.setSamlSsoUrl(ssoUrl);
            if (certificate != null) config.setSamlX509Certificate(certificate);
            if (acsUrl != null) config.setSamlAcsUrl(acsUrl);
            if (priority != null) config.setPriority(priority);

            // Regenerate SP Metadata if entityId or acsUrl changed
            if (entityId != null || acsUrl != null) {
                String spMetadata = samlMetadataService.generateSpMetadata(
                        config.getSamlEntityId(),
                        config.getSamlAcsUrl()
                );
                config.setSamlSpMetadata(spMetadata);
            }

            config.setLastModifiedBy(modifiedBy);
            config.setLastModifiedAt(LocalDateTime.now());
            return ssoConfigRepository.save(config);
        }
        return null;
    }

    /**
     * Parse and save IDP metadata for SAML
     */
    public Map<String, String> parseIdpMetadata(String metadataXml) {
        return samlMetadataService.parseIdpMetadata(metadataXml);
    }

    /**
     * Delete SSO configuration
     */
    public boolean deleteSsoConfig(Long id) {
        if (ssoConfigRepository.existsById(id)) {
            ssoConfigRepository.deleteById(id);
            return true;
        }
        return false;
    }

    /**
     * Get JWT SSO URL for specific config
     */
    public String getJwtSsoUrl(Long configId) {
        SsoConfig config = getSsoConfigById(configId);
        if (config == null || !config.getEnabled()) {
            return null;
        }

        String ssoUrl = config.getJwtSsoUrl();
        String callbackUrl = config.getJwtCallbackUrl();

        if (ssoUrl == null || ssoUrl.isEmpty()) {
            return null;
        }

        // Append callback URL if provided
        if (callbackUrl != null && !callbackUrl.isEmpty()) {
            if (ssoUrl.contains("?")) {
                return ssoUrl + "&RelayState=" + callbackUrl + "&config_id=" + configId;
            } else {
                return ssoUrl + "?RelayState=" + callbackUrl + "&config_id=" + configId;
            }
        }

        return ssoUrl;
    }
}