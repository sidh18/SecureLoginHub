package com.example.loginapp.security;

import com.example.loginapp.model.user; // Ensure you have this import
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails extends User {

    private final Long organizationId;

    /**
     * --- THIS IS THE NEW CONSTRUCTOR ---
     * This is the 1-argument constructor that CustomUserDetailsService needs.
     */
    public CustomUserDetails(user user) {
        // --- FIX: ---
        // We MUST use the full 7-argument super() constructor to pass the
        // user's 'enabled' status.
        super(
                user.getUsername(),
                user.getPassword(),
                // Safely check the Boolean 'active' field.
                // (user.getActive() != null && user.getActive()) treats null as false.
                user.getActive() != null && user.getActive(), // enabled
                true, // accountNonExpired
                true, // credentialsNonExpired
                true, // accountNonLocked
                List.of(new SimpleGrantedAuthority(user.getRole()))
        );
        // --- END FIX ---

        this.organizationId = (user.getOrganization() != null) ? user.getOrganization().getId() : null;
    }

    /**
     * This 4-argument constructor is used by the JwtAuthenticationFilter
     * It defaults all boolean flags to 'true', which is fine for JWT.
     */
    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities, Long organizationId) {
        super(username, password, authorities);
        this.organizationId = organizationId;
    }

    // Getters for our custom fields
    public Long getOrganizationId() {
        return organizationId;
    }

    public boolean isSuperAdmin() {
        return organizationId == null;
    }

    public String getMainRole() {
        return getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse(null);
    }
}
