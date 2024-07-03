package com.example.security.service;

import com.example.security.dto.*;
import com.example.security.entity.Token;
import com.example.security.entity.User;
import com.example.security.repository.TokenRepository;
import com.example.security.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository repository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final TokenRepository tokenRepository;

    private final AuthenticationManager authenticationManager;


    /**
     * Registers a new user with the provided registration details.
     * If the user already exists, authentication is performed instead.
     *
     * @param request The registration request containing user details.
     * @return An AuthenticationResponse object containing access and refresh tokens
     *         along with a message indicating the success or failure of the registration process.
     */
    public AuthenticationResponse register(RegisterRequest request) {
        // check if user already exist. if exist than authenticate the user
        if(repository.findUserByEmail(request.getEmail()).isPresent()) {
            return AuthenticationResponse.builder().message("User already exist").build();
        }
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(request.getRole())
                .build();

        user = repository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(accessToken, user);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message("User register successfully")
                .build();
    }

    /**
     * Authenticates a user based on the provided login credentials.
     * If authentication is successful, generates access and refresh tokens for the user.
     *
     * @param request The login request containing user credentials.
     * @return An AuthenticationResponse object containing access and refresh tokens
     *         along with a message indicating the success or failure of the authentication process.
     * @throws AuthenticationException if authentication fails.
     * @throws EntityNotFoundException if the user corresponding to the provided username is not found.
     */
    public AuthenticationResponse authenticate(LoginRequest request) {
            try {
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.getUsername(),
                                request.getPassword()
                        )
                );
            } catch (AuthenticationException e){
                log.error(e.getMessage());
                throw e;
            }


            User user = repository.findUserByEmail(request.getUsername()).orElseThrow(EntityNotFoundException::new);
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllTokenByUser(user);
            saveUserToken(accessToken, user);

            return AuthenticationResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .message("User login successfully")
                    .build();

    }


    /**
     * Refreshes the access token using the provided refresh token.
     * If the refresh token is valid, generates a new access token for the user.
     *
     * @param request  The HttpServletRequest containing the refresh token in the Authorization header.
     * @param response The HttpServletResponse used to send the new access token to the client.
     * @throws IOException if an I/O error occurs while writing the new access token to the response.
     */
    public AuthenticationResponse refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return AuthenticationResponse.builder().message("Invalid Refresh Token").build();
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findUserByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllTokenByUser(user);
                saveUserToken(accessToken,user);
                return AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
            }
        }
        return AuthenticationResponse.builder().message("Something Wrong !").build();
    }

    /**
     * Changes the password of the currently connected user.
     *
     * @param request        The request containing the current and new passwords.
     * @param connectedUser  The principal representing the currently connected user.
     * @throws IllegalStateException if the current password is incorrect or if the new passwords do not match.
     */
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Wrong password");
        }
        // check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Password are not the same");
        }

        // update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // save the new password
        repository.save(user);
    }


    /**
     * Revokes all tokens associated with the specified user by marking them as logged out.
     * If no tokens are associated with the user, the method returns without performing any action.
     *
     * @param user The user for whom tokens need to be revoked.
     */
    private void revokeAllTokenByUser(User user) {
        List<Token> validTokens = tokenRepository.findAllTokensByUser(user.getId());
        if(validTokens.isEmpty()) {
            return;
        }

        validTokens.forEach(t-> {
            t.setLoggedOut(true);
        });

        tokenRepository.saveAll(validTokens);
    }

    /**
     * Saves the user's token in the token repository.
     *
     * @param jwt  The JWT token to be saved.
     * @param user The user associated with the token.
     */
    private void saveUserToken(String jwt, User user) {
        Token token = new Token();
        token.setToken(jwt);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

//    @Async("asyncTaskExecutor")
//    public void getJsonRes(){
//        System.out.println("Execute method with configured executor - "
//                + Thread.currentThread().getName());
//        RestTemplate restTemplate = new RestTemplate();
//        JsonMockResponse result = restTemplate.getForObject("https://jsonplaceholder.typicode.com/posts/1", JsonMockResponse.class);
//        System.out.println(result != null ? result.toString() : "null");
//    }
}
