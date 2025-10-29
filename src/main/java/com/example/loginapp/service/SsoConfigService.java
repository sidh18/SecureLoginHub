package com.example.loginapp.service;

import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.repository.SsoConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class SsoConfigService {

    @Autowired
    private SsoConfigRepository ssoConfigRepository;

    public SsoConfig getSsoConfig() {
        return ssoConfigRepository.findFirstByOrderByIdDesc()
                .orElse(new SsoConfig());
    }



    public boolean isSsoEnabled() {
        SsoConfig config = getSsoConfig();
        return config.getSsoEnabled() != null && config.getSsoEnabled();
    }

    public String getSsoType() {
        SsoConfig config = getSsoConfig();
        return config.getSsoType();
    }

    public SsoConfig toggleSso(boolean enabled, String modifiedBy) {
        SsoConfig config = getSsoConfig();
        config.setSsoEnabled(enabled);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    public SsoConfig saveJwtConfig(String clientId, String ssoUrl, String callbackUrl,
                                   String logoutUrl, String modifiedBy) {
        SsoConfig config = getSsoConfig();
        config.setSsoEnabled(true);
        config.setSsoType("JWT");
        config.setJwtClientId(clientId);
        config.setJwtSsoUrl(ssoUrl);
        config.setJwtCallbackUrl(callbackUrl);
        config.setJwtLogoutUrl(logoutUrl);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    public SsoConfig saveOAuthConfig(String clientId, String clientSecret,
                                     String authUrl, String tokenUrl, String callbackUrl,
                                     String modifiedBy) {
        SsoConfig config = getSsoConfig();
        config.setSsoEnabled(true);
        config.setSsoType("OAUTH");
        config.setOauthClientId(clientId);
        config.setOauthClientSecret(clientSecret);
        config.setOauthAuthorizationUrl(authUrl);
        config.setOauthTokenUrl(tokenUrl);
        config.setOauthCallbackUrl(callbackUrl);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    public SsoConfig saveSamlConfig(String entityId, String ssoUrl,
                                    String certificate, String callbackUrl,
                                    String modifiedBy) {
        SsoConfig config = getSsoConfig();
        config.setSsoEnabled(true);
        config.setSsoType("SAML");
        config.setSamlEntityId(entityId);
        config.setSamlSsoUrl(ssoUrl);
        config.setSamlX509Certificate(certificate);
        config.setSamlCallbackUrl(callbackUrl);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    public String getJwtSsoUrl() {
        SsoConfig config = getSsoConfig();
        String ssoUrl = config.getJwtSsoUrl();
        String callbackUrl = config.getJwtCallbackUrl();

        if (ssoUrl == null || ssoUrl.isEmpty()) {
            return null;
        }

        // Append callback URL if provided
        if (callbackUrl != null && !callbackUrl.isEmpty()) {
            if (ssoUrl.contains("?")) {
                return ssoUrl + "&RelayState=" + callbackUrl;
            } else {
                return ssoUrl + "?RelayState=" + callbackUrl;
            }
        }

        return ssoUrl;
    }

    public String getJwtLogoutUrl() {
        SsoConfig config = getSsoConfig();
        return config.getJwtLogoutUrl();
    }
}