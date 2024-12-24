package org.example.yogabusinessmanagementweb.dto.response.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.io.Serializable;

@Getter
@AllArgsConstructor
@Builder

public class TokenRespone implements Serializable {
    private String accesstoken;
    private String refreshtoken;
    private long userid;
}
