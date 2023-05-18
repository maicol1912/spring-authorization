package com.spring.jwt.Jwtspring.controller;

import com.spring.jwt.Jwtspring.dto.LoginRequest;
import com.spring.jwt.Jwtspring.dto.UserDTO;
import com.spring.jwt.Jwtspring.jwt.JwtService;
import com.spring.jwt.Jwtspring.service.UserService;
import com.spring.jwt.Jwtspring.service.security.UserDetailCustom;
import com.spring.jwt.Jwtspring.utilities.BaseResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.AuthenticationProvider;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/account")
@RequiredArgsConstructor
public class AccountController {

    private final UserService userService;
    private final AuthenticationProvider authenticationProvider;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<BaseResponseDTO>register(@RequestBody UserDTO userDTO){
         return ResponseEntity.ok(userService.registerAccount(userDTO));
     }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequest request){
        authenticateUser(request.getUsername(), request.getPassword());
        UserDetailCustom userDetails = (UserDetailCustom) userDetailsService.loadUserByUsername(request.getUsername());
        String token = jwtService.generateToken(userDetails);
        Map response =  new HashMap();
        response.put("jwt",token);
        return ResponseEntity.ok(response);
    }

    private void authenticateUser(String username, String password) {
        authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
