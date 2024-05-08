package com.example.security.constant;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum ErrorCode {

    SYSTEM_ERROR_CODE("001");

    private final String value;

    @Override
    public String toString() {
        return "Error Code: " + value;
    }

}
