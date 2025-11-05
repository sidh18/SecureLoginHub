package com.example.loginapp.repository;

import com.example.loginapp.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    /**
     * Finds an organization by its unique subdomain.
     * This is the core query for our tenant filter.
     * e.g., "acme" -> Organization(id=5, name="Acme Corp", subdomain="acme")
     */
    Optional<Organization> findBySubdomain(String subdomain);
}
