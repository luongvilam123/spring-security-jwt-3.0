package com.example.security.dto;

import com.example.security.constant.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class RegisterRequest {

    private String firstName;

    private String lastName;

    private String username;

    private String password;

    private String email;

    private Role role;
}
