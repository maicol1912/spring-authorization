package com.spring.jwt.Jwtspring.jwt;

import com.spring.jwt.Jwtspring.service.security.UserDetailCustom;
import io.jsonwebtoken.Claims;

import java.security.Key;

public interface JwtService {

    Claims extractClaims(String token);

    Key getKey();

    String generateToken(UserDetailCustom userDetailCustom);

    boolean isValidToken(String token);
}
