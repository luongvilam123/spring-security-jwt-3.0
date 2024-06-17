package com.example.security.config;

import com.example.security.entity.Token;
import com.example.security.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
public class CustomLogoutHandler implements LogoutHandler {

    private final TokenRepository tokenRepository;

    public CustomLogoutHandler(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    /**
     * Handles the logout functionality for an authenticated user.
     * This method checks for the presence of an authorization header,
     * validates the token, and marks the token as logged out in the repository.
     *
     * @param request        the {@code HttpServletRequest} containing the logout
     *                       request details
     * @param response       the {@code HttpServletResponse} for sending responses
     *                       to the client
     * @param authentication the {@code Authentication} object containing
     *                       authentication details of the current user
     */
    @Override
    public void logout(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        String token = authHeader.substring(7);
        Token storedToken = tokenRepository.findByToken(token).orElse(null);

        if (storedToken != null) {
            storedToken.setLoggedOut(true);
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}
