package com.example.loginapp.service;

import com.example.loginapp.model.Organization;
import com.example.loginapp.model.SsoConfig;
import com.example.loginapp.repository.OrganizationRepository;
import com.example.loginapp.repository.SsoConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.time.Instant; // <-- We will use this
import java.time.LocalDateTime; // <-- We will stop using this for .now()
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class SsoConfigService {

    @Autowired
    private SsoConfigRepository ssoConfigRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    // --- Tenant-Aware Getters ---

    /**
     * Gets all SSO configs for a specific organization (for Tenant Admins).
     */
    public List<SsoConfig> getAllSsoConfigsForOrganization(Long organizationId) {
        if (organizationId == null) {
            throw new IllegalArgumentException("Organization ID cannot be null");
        }
        return ssoConfigRepository.findByOrganizationId(organizationId);
    }

    /**
     * Gets all SSO configs for Superadmins (global and all tenant configs).
     * This is a "god mode" view.
     */
    public List<SsoConfig> getAllSsoConfigsForSuperAdmin() {
        return ssoConfigRepository.findAll();
    }

    /**
     * Gets a single SSO config, ensuring it belongs to the correct organization.
     */
    public SsoConfig getSsoConfigById(Long configId, Long organizationId) throws Exception {
        SsoConfig config = ssoConfigRepository.findById(configId)
                .orElseThrow(() -> new Exception("SSO Config not found"));

        // Security check
        if (organizationId != null) { // This is a Tenant Admin
            if (config.getOrganization() == null || !config.getOrganization().getId().equals(organizationId)) {
                throw new Exception("Access Denied: SSO Config not found.");
            }
        }
        // Superadmin (null orgId) can get any config

        return config;
    }

    /**
     * Gets the single enabled config of a specific type for a specific organization.
     * This is called by the SSO controllers during login.
     */
    public SsoConfig getEnabledSsoConfig(String ssoType, Long organizationId) {
        if (organizationId == null) {
            // Superadmin domain has no SSO by default.
            // Or you could have global SSO configs (orgId=null).
            // For now, we'll assume SSO is tenant-only.
            return null;
        }
        return ssoConfigRepository.findBySsoTypeAndEnabledTrueAndOrganizationId(ssoType, organizationId)
                .orElse(null);
    }

    /**
     * Finds a config by its client ID, only within a specific organization.
     * Used for the JWT SSO callback.
     */
    public SsoConfig findByJwtClientId(String clientId, Long organizationId) {
        if (organizationId == null) {
            return null;
        }
        return ssoConfigRepository.findByJwtClientIdAndOrganizationId(clientId, organizationId)
                .orElse(null);
    }

    // --- NEW METHOD ---
    /**
     * Gets all ENABLED SSO configs for a specific organization.
     * This is the missing method called by ApiController for the login page.
     */
    public List<SsoConfig> getEnabledSsoConfigsForOrganization(Long organizationId) {
        if (organizationId == null) {
            return Collections.emptyList();
        }
        // Get all configs for the org (we know this repo method exists from other methods)
        List<SsoConfig> allConfigs = ssoConfigRepository.findByOrganizationId(organizationId);

        // Filter in-memory for only the enabled ones.
        // We can safely assume SsoConfig has 'isEnabled()' because 'setEnabled(false)'
        // is called in your save methods.
        return allConfigs.stream()
                .filter(SsoConfig::isEnabled)
                .collect(Collectors.toList());
    }

    // --- Tenant-Aware C.R.U.D. Methods ---
    // All save/update/delete methods now require an organizationId
    // to correctly assign the config to a tenant.

    private Organization getOrg(Long organizationId) throws Exception {
        if (organizationId == null) {
            return null; // This is a "global" config made by a Superadmin
        }
        return organizationRepository.findById(organizationId)
                .orElseThrow(() -> new Exception("Organization not found"));
    }

    public SsoConfig saveJwtConfig(String name, String clientId, String ssoUrl, String callbackUrl,
                                   String logoutUrl, Integer priority, String modifiedBy, Long organizationId) throws Exception {

        SsoConfig config = new SsoConfig();
        config.setSsoType("JWT");
        config.setName(name);
        config.setJwtClientId(clientId);
        config.setJwtSsoUrl(ssoUrl);
        config.setJwtCallbackUrl(callbackUrl);
        config.setJwtLogoutUrl(logoutUrl);
        config.setPriority(priority);
        config.setEnabled(false); // New configs are disabled by default
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 1
        config.setOrganization(getOrg(organizationId));

        return ssoConfigRepository.save(config);
    }

    public SsoConfig updateJwtConfig(Long id, String name, String clientId, String ssoUrl, String callbackUrl,
                                     String logoutUrl, Integer priority, String modifiedBy, Long organizationId) throws Exception {

        SsoConfig config = getSsoConfigById(id, organizationId); // Security check

        config.setSsoType("JWT");
        config.setName(name);
        config.setJwtClientId(clientId);
        config.setJwtSsoUrl(ssoUrl);
        config.setJwtCallbackUrl(callbackUrl);
        config.setJwtLogoutUrl(logoutUrl);
        config.setPriority(priority);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 2
        // We don't change the organization on update

        return ssoConfigRepository.save(config);
    }

    public SsoConfig saveOAuthConfig(String name, String clientId, String clientSecret, String authUrl,
                                     String tokenUrl, String callbackUrl, String userInfoUrl,
                                     Integer priority, String modifiedBy, Long organizationId) throws Exception {

        SsoConfig config = new SsoConfig();
        config.setSsoType("OAUTH");
        config.setName(name);
        config.setOauthClientId(clientId);
        config.setOauthClientSecret(clientSecret);
        config.setOauthAuthorizationUrl(authUrl);
        config.setOauthTokenUrl(tokenUrl);
        config.setOauthCallbackUrl(callbackUrl);
        config.setOauthUserInfoUrl(userInfoUrl);
        config.setPriority(priority);
        config.setEnabled(false);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 3
        config.setOrganization(getOrg(organizationId));

        return ssoConfigRepository.save(config);
    }

    public SsoConfig updateOAuthConfig(Long id, String name, String clientId, String clientSecret,
                                       String authUrl, String tokenUrl, String callbackUrl, String userInfoUrl,
                                       Integer priority, String modifiedBy, Long organizationId) throws Exception {

        SsoConfig config = getSsoConfigById(id, organizationId); // Security check

        config.setSsoType("OAUTH");
        config.setName(name);
        config.setOauthClientId(clientId);
        config.setOauthClientSecret(clientSecret);
        config.setOauthAuthorizationUrl(authUrl);
        config.setOauthTokenUrl(tokenUrl);
        config.setOauthCallbackUrl(callbackUrl);
        config.setOauthUserInfoUrl(userInfoUrl);
        config.setPriority(priority);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 4

        return ssoConfigRepository.save(config);
    }

    public SsoConfig saveSamlConfig(String name, String entityId, String idpEntityId, String ssoUrl,
                                    String certificate, String acsUrl,
                                    Integer priority, String modifiedBy, Long organizationId) throws Exception {

        SsoConfig config = new SsoConfig();
        config.setSsoType("SAML");
        config.setName(name);
        config.setSamlEntityId(entityId);
        config.setSamlIdpEntityId(idpEntityId);
        config.setSamlSsoUrl(ssoUrl);
        config.setSamlX509Certificate(certificate);
        config.setSamlAcsUrl(acsUrl);
        config.setPriority(priority);
        config.setEnabled(false);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 5
        config.setOrganization(getOrg(organizationId));

        return ssoConfigRepository.save(config);
    }

    public SsoConfig updateSamlConfig(Long id, String name, String entityId, String idpEntityId,
                                      String ssoUrl, String certificate, String acsUrl,
                                      Integer priority, String modifiedBy, Long organizationId) throws Exception {

        SsoConfig config = getSsoConfigById(id, organizationId); // Security check

        config.setSsoType("SAML");
        config.setName(name);
        config.setSamlEntityId(entityId);
        config.setSamlIdpEntityId(idpEntityId);
        config.setSamlSsoUrl(ssoUrl);
        config.setSamlX509Certificate(certificate);
        config.setSamlAcsUrl(acsUrl);
        config.setPriority(priority);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 6

        return ssoConfigRepository.save(config);
    }

    public boolean deleteSsoConfig(Long id, Long organizationId) throws Exception {
        SsoConfig config = getSsoConfigById(id, organizationId); // Security check
        ssoConfigRepository.delete(config);
        return true;
    }

    public SsoConfig toggleSso(Long id, boolean enabled, String modifiedBy, Long organizationId) throws Exception {
        SsoConfig config = getSsoConfigById(id, organizationId); // Security check

        // --- NEW LOGIC: Only one config of each type can be enabled per org ---
        if (enabled) {
            // Before enabling this one, disable all others of the same type in this org
            List<SsoConfig> otherConfigs = ssoConfigRepository.findByOrganizationId(organizationId);
            for (SsoConfig other : otherConfigs) {
                if (other.getSsoType().equals(config.getSsoType()) && !other.getId().equals(id)) {
                    other.setEnabled(false);
                    ssoConfigRepository.save(other);
                }
            }
        }

        config.setEnabled(enabled);
        config.setLastModifiedBy(modifiedBy);
        config.setLastModifiedAt(Instant.now()); // <--- FIX 7
        return ssoConfigRepository.save(config);
    }

    // --- Metadata Parsing (unchanged, as it's just a helper) ---

    public Map<String, String> parseIdpMetadata(String metadataXml) throws Exception {
        Map<String, String> data = new HashMap<>();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // Prevent XML External Entity (XXE) attacks
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(metadataXml)));
        doc.getDocumentElement().normalize();

        // Get IDP Entity ID
        Element idpEntityIdElement = (Element) doc.getElementsByTagName("md:EntityDescriptor").item(0);
        if (idpEntityIdElement != null) {
            data.put("entityId", idpEntityIdElement.getAttribute("entityID"));
        }

        // Get SSO URL (HTTP-Redirect)
        Element ssoElement = (Element) doc.getElementsByTagName("md:SingleSignOnService").item(0);
        if (ssoElement != null) {
            data.put("ssoUrl", ssoElement.getAttribute("Location"));
        }

        // Get X.509 Certificate
        Element certElement = (Element) doc.getElementsByTagName("ds:X509Certificate").item(0);
        if (certElement != null) {
            data.put("certificate", certElement.getTextContent());
        }

        return data;
    }
}

