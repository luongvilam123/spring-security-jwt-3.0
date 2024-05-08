package com.example.security.exception;

import com.example.security.constant.ErrorCode;
import lombok.Getter;



@Getter
public class DomainException extends RuntimeException{

    private final String message;

    public DomainException(ErrorCode errorCode){
        this.message = errorCode.toString();
    }

}
