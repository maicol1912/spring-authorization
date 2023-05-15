package com.spring.jwt.Jwtspring.service;

import com.spring.jwt.Jwtspring.dto.UserDTO;
import com.spring.jwt.Jwtspring.utilities.BaseResponseDTO;
import org.springframework.stereotype.Service;


public interface UserService {
    BaseResponseDTO registerAccount(UserDTO userDTO);
}
