package com.example.security.controller;

import com.example.security.dto.ChangePasswordRequest;
import com.example.security.dto.RegisterRequest;
import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import com.example.security.dto.AuthenticationResponse;
import com.example.security.dto.LoginRequest;
import com.example.security.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.Principal;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user/")
@Tag(name = "Management")
public class UserController {

    final private AuthenticationService authService;
    final private UserRepository userRepository;

    @Operation(
            description = "This Endpoint is for User Register",
            summary = "User Register",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "403"
                    )
            }

    )
    @PostMapping("register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody LoginRequest request
    ) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @PostMapping("refresh-token")
    public AuthenticationResponse  getRefreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        return authService.refreshToken(request, response);
    }

    @PostMapping("change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest request,
            Principal connectedUser
    ) {
        authService.changePassword(request, connectedUser);
        return ResponseEntity.ok().build();
    }

    @GetMapping("create-audit-user")
    public String createAuditUser() {
        User user = new User();
        user.setEmail("testEMail@gmail.com");
        user.setUsername("testUserName");
        userRepository.save(user);
        return "Create new user success";
    }

    @GetMapping("modified-audit-user")
    public String getMethodName(@RequestParam String param) {
        return new String();
    }
    
    

}
