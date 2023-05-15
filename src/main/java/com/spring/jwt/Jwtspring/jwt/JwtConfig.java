package com.spring.jwt.Jwtspring.jwt;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;

@Data
public class JwtConfig {

    @Value("${jwt.url:/jwt/login}")
    private String url;
    @Value("${jwt.header:Authorization}")
    private String header;
    @Value("${jwt.prefix:Bearer}")
    private String prefix;
    @Value("${jwt.expiration:#{60*60}}")
    private int expiration;
    @Value("${jwt.secret:472D4B6150645367566B59703373367639792442264529482B4D625165546857}")
    private String secret;
}
