package com.spring.jwt.Jwtspring.service.security;

import com.spring.jwt.Jwtspring.entity.User;
import com.spring.jwt.Jwtspring.exception.BaseException;
import com.spring.jwt.Jwtspring.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.ObjectUtils;

import java.util.stream.Collectors;


public class UserDetailServiceCustom implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetailCustom userDetailCustom = getUserDetails(username);
        if(ObjectUtils.isEmpty(userDetailCustom)){
            throw new BaseException(String.valueOf(HttpStatus.BAD_REQUEST.value()),"Invalid Username or password");
        }
        return userDetailCustom;
    }

    private UserDetailCustom getUserDetails(String username){
        User user = userRepository.findByUsername(username);

        if(ObjectUtils.isEmpty(user)){
            throw new BaseException(String.valueOf(HttpStatus.BAD_REQUEST.value()),"Invalid Username or password");
        }
        return new UserDetailCustom(
                user.getUsername(),
                user.getPassword(),
                user.getRoles().stream().map(r-> new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList())
        );
    }
}
