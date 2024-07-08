package com.example.security.config;

import com.example.security.service.JwtFilterAuthentication;
import com.example.security.service.UserDetailsImp;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final UserDetailsImp userDetailsServiceImp;

        private final JwtFilterAuthentication jwtAuthenticationFilter;

        private final CustomLogoutHandler logoutHandler;

        private static final String[] WHITE_LIST_URL = {
                        "/api/v1/user/login",
                        "/api/v1/user/register",
                        "/api/v1/user/refresh-token",
                        "/v3/api-docs/**",
                        "/swagger-resources/**",
                        "/configuration/ui",
                        "/configuration/security",
                        "/swagger-ui/**",
                        "/webjars/**",
                        "/swagger-ui.html"
        };

        /**
         * Creates and configures an {AuthenticationProvider} bean.
         * This bean is used for authentication purposes, utilizing a
         * {UserDetailsService}
         * and a password encoder.
         *
         * @return an {AuthenticationProvider} configured with user details
         *         service and password encoder
         */
        @Bean
        AuthenticationProvider authenticationProvider() {
                DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
                authProvider.setUserDetailsService(userDetailsServiceImp);
                authProvider.setPasswordEncoder(passwordEncoder());
                return authProvider;
        }

        /**
         * Configures the security filter chain for the application.
         * This method sets up the security configurations including CSRF, request
         * authorization,
         * user details service, session management, JWT authentication filter,
         * exception handling, and logout functionality.
         *
         * @param http the {@code HttpSecurity} to modify the default security
         *             configurations
         * @return a configured {@code SecurityFilterChain} object
         * @throws Exception if an error occurs while building the security filter chain
         */
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

                return http
                                .csrf(AbstractHttpConfigurer::disable)
                                .authorizeHttpRequests(
                                                req -> req.requestMatchers(WHITE_LIST_URL)
                                                                .permitAll()
                                                                // .requestMatchers("/api/test/admin_only/**").hasAuthority(Role.ADMIN.name())
                                                                // .requestMatchers("/admin_only/authority/**").hasRole(Role.ADMIN.name())
                                                                .anyRequest()
                                                                .authenticated())
                                .userDetailsService(userDetailsServiceImp)
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                                .exceptionHandling(
                                                e -> e.accessDeniedHandler(
                                                                (request, response, accessDeniedException) -> response
                                                                                .setStatus(403))
                                                                .authenticationEntryPoint(new HttpStatusEntryPoint(
                                                                                HttpStatus.UNAUTHORIZED)))
                                .logout(l -> l
                                                .logoutUrl("/logout")
                                                .addLogoutHandler(logoutHandler)
                                                .logoutSuccessHandler((request, response,
                                                                authentication) -> SecurityContextHolder
                                                                                .clearContext()))
                                .build();

        }

        /**
         * Defines a PasswordEncoder bean that uses BCrypt hashing algorithm.
         * 
         * @return a BCryptPasswordEncoder instance.
         */
        @Bean
        PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        /**
         * Defines an AuthenticationManager bean by retrieving the default
         * AuthenticationManager
         * from the provided AuthenticationConfiguration.
         * 
         * @param configuration the AuthenticationConfiguration to retrieve the
         *                      AuthenticationManager from.
         * @return the AuthenticationManager instance.
         * @throws Exception if an error occurs while retrieving the
         *                   AuthenticationManager.
         */
        @Bean
        AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
                return configuration.getAuthenticationManager();
        }

        /**
         * Defines an AuditorAware bean that provides the current auditor for auditing
         * purposes.
         * 
         * @return an ApplicationAuditAware instance.
         */
        @Bean
        AuditorAware<String> auditorAware() {
                return new ApplicationAuditAware();
        }

}
