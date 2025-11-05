package com.example.loginapp.repository;

import com.example.loginapp.model.user;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query; // <-- IMPORT THIS
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<user, Long> {

    Optional<user> findByUsername(String username);

    Optional<user> findByEmail(String email);

    // --- NEW MULTI-TENANT QUERIES ---

    Optional<user> findByEmailAndOrganizationId(String email, Long organizationId);

    List<user> findByOrganizationId(Long organizationId);

    Optional<user> findByUsernameAndOrganizationId(String username, Long organizationId);

    /**
     * Finds a user by username, only for users with NO organization.
     * This is used to log in the Superadmin.
     */
    Optional<user> findByUsernameAndOrganizationIdIsNull(String username);

    List<user> findByOrganizationIdIsNull();

    // --- THIS IS THE FIX ---
    /**
     * Finds all users and eagerly fetches their organization.
     * This prevents LazyInitializationException when serializing for the admin dashboard.
     * We use LEFT JOIN FETCH to ensure we still get Superadmins (who have no org).
     */
    @Query("SELECT u FROM user u LEFT JOIN FETCH u.organization")
    List<user> findAllWithOrganization();
}
