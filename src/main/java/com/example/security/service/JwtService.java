package com.example.security.service;

import com.example.security.entity.User;
import com.example.security.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

/**
 This Class is used to generate and validate JWT Token
*/

@Service
@RequiredArgsConstructor
public class JwtService {

    private final TokenRepository tokenRepository;

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    /**
     * Extract Claims from JWT
     * @param token the JWT Token
     * @return the username that using to log in
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Check if the token is valid or invalid
     * @param token the JWT Token
     * @param user the User related
     * @return if a token is valid or invalid
     */
    public boolean isValid(String token, UserDetails user) {
        String email = extractUsername(token);
        // boolean validToken = tokenRepository
        //         .findByToken(token)
        //         .map(t -> !t.isLoggedOut())
        //         .orElse(false);

        return (email.equals(user.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Check if a token is expired or not
     * @param token The JWT Token
     * @return true or  false
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Get extract expiration from JWT Token
     * @param token thw JWT Token
     * @return the expired date
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(User user) {
        return buildToken(user, jwtExpiration);
    }

    public String generateRefreshToken(User user) {
        return buildToken(user, refreshExpiration);
    }

    public String buildToken(User user, long expiration) {
        return Jwts
                .builder()
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
