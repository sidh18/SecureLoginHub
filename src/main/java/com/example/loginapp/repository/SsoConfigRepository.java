package com.example.loginapp.repository;

import com.example.loginapp.model.SsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoConfigRepository extends JpaRepository<SsoConfig, Long> {

    // --- NEW MULTI-TENANT QUERIES ---

    /**
     * Finds all SSO configs for a specific organization.
     * This is what a Tenant Admin will use.
     */
    List<SsoConfig> findByOrganizationId(Long organizationId);

    /**
     * Finds all SSO configs that are "global" (not tied to an organization).
     * These are manageable only by a Superadmin.
     */


    /**
     * Finds an enabled config of a specific type for a specific organization.
     * Used for the tenant's SSO login flow.
     */
    Optional<SsoConfig> findBySsoTypeAndEnabledTrueAndOrganizationId(String ssoType, Long organizationId);

    /**
     * Finds the config by its Client ID (iss claim) for a specific organization.
     * (This might be more secure for the JWT callback)
     */
    Optional<SsoConfig> findByJwtClientIdAndOrganizationId(String clientId, Long organizationId);
}
