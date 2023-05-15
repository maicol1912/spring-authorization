package com.spring.jwt.Jwtspring.controller;

import com.spring.jwt.Jwtspring.dto.UserDTO;
import com.spring.jwt.Jwtspring.service.UserService;
import com.spring.jwt.Jwtspring.utilities.BaseResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/account")
@RequiredArgsConstructor
public class AccountController {

    private final UserService userService;

     @PostMapping("/register")
    public ResponseEntity<BaseResponseDTO>register(@RequestBody UserDTO userDTO){
         return ResponseEntity.ok(userService.registerAccount(userDTO));
     }
}
