package com.spring.jwt.Jwtspring.service.impl;

import com.spring.jwt.Jwtspring.dto.UserDTO;
import com.spring.jwt.Jwtspring.entity.Role;
import com.spring.jwt.Jwtspring.entity.User;
import com.spring.jwt.Jwtspring.exception.BaseException;
import com.spring.jwt.Jwtspring.repository.RoleRepository;
import com.spring.jwt.Jwtspring.repository.UserRepository;
import com.spring.jwt.Jwtspring.service.UserService;
import com.spring.jwt.Jwtspring.utilities.BaseResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public BaseResponseDTO registerAccount(UserDTO userDTO) {
        BaseResponseDTO response = new BaseResponseDTO();

        validateAccount(userDTO);

        User user = insertUser(userDTO);
        try {
            userRepository.save(user);
            response.setCode(String.valueOf(HttpStatus.OK.value()));
            response.setMessage("Create Account successfully");
        }catch (Exception e){
            response.setCode(String.valueOf(HttpStatus.SERVICE_UNAVAILABLE.value()));
            response.setMessage("Service Unvaliable");
        }
        return response;
    }

    private User insertUser(UserDTO userDTO){
        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(userDTO.getRole()));
        user.setRoles(roles);
        return user;
    }
    private void validateAccount(UserDTO userDTO){
        //* validate null data
        if(ObjectUtils.isEmpty(userDTO)){
            throw new BaseException(String.valueOf(HttpStatus.BAD_REQUEST.value()),"Data must not empty");
        }
        //* validate duplicate username
        User user = userRepository.findByUsername(userDTO.getUsername());
        if(!ObjectUtils.isEmpty(user)){
            throw new BaseException(String.valueOf(HttpStatus.BAD_REQUEST.value()),"Username had existed");
        }
        //* validate role
        List<String> roles = roleRepository.findAll().stream().map(Role::getName).toList();
        if(!roles.contains(userDTO.getRole())){
            throw new BaseException(String.valueOf(HttpStatus.BAD_REQUEST.value()),"Invalid Role");
        }
    }
}
