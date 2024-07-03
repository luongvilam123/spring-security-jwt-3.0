package com.example.security.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString
public class JsonMockResponse {

    public int userId;

    public int id;

    public String title;

    public String body;

}
