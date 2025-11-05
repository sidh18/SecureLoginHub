package com.example.loginapp.config;

import com.example.loginapp.model.Organization;

// This class holds the information for the *current* request
public class TenantContext {

    // A ThreadLocal variable will hold data privately for each thread (i.e., for each request)
    private static final ThreadLocal<Long> currentOrganizationId = new ThreadLocal<>();
    private static final ThreadLocal<String> currentSubdomain = new ThreadLocal<>();

    // --- Organization ID Methods ---

    public static void setCurrentOrganizationId(Long organizationId) {
        if (organizationId == null) {
            currentOrganizationId.remove();
        } else {
            currentOrganizationId.set(organizationId);
        }
    }

    public static Long getCurrentOrganizationId() {
        return currentOrganizationId.get();
    }

    // --- Subdomain Methods (This fixes your error) ---

    public static void setCurrentSubdomain(String subdomain) {
        if (subdomain == null) {
            currentSubdomain.remove();
        } else {
            currentSubdomain.set(subdomain);
        }
    }

    public static String getCurrentSubdomain() {
        return currentSubdomain.get();
    }

    // --- Clear Method ---

    public static void clear() {
        currentOrganizationId.remove();
        currentSubdomain.remove();
    }
}


