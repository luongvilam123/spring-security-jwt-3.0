package com.example.security.config;

import java.util.Optional;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.example.security.entity.User;

public class ApplicationAuditAware implements AuditorAware<String> {

    // Enable CreatedBy and LastModifiedBy
    /**
     * This class provides the implementation for retrieving the current auditor's
     * information.
     * The auditor is typically the currently authenticated user.
     */
    @SuppressWarnings("null")
    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();
        if (authentication == null ||
                !authentication.isAuthenticated() ||
                authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }

        User userPrincipal = (User) authentication.getPrincipal();
        return Optional.ofNullable(userPrincipal.getFirstName());
    }
}