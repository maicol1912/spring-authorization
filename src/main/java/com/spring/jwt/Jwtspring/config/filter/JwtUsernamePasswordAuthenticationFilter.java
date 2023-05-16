package com.spring.jwt.Jwtspring.config.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.jwt.Jwtspring.dto.LoginRequest;
import com.spring.jwt.Jwtspring.jwt.JwtConfig;
import com.spring.jwt.Jwtspring.jwt.JwtService;
import com.spring.jwt.Jwtspring.service.security.UserDetailCustom;
import com.spring.jwt.Jwtspring.utilities.BaseResponseDTO;
import com.spring.jwt.Jwtspring.utilities.HelperUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.Collections;

//*El filtro se activa cuando un cliente realiza una solicitud POST a la URL configurada en el archivo de configuración de
//* JwtConfig. En este caso, el filtro llama a un objeto AuthenticationManager que maneja la autenticación.

//*El cuerpo de la solicitud debe contener un objeto LoginRequest que contiene el nombre de usuario y la contraseña. Después de leer la
//* solicitud, el filtro llama a getAuthenticationManager() para autenticar el nombre de usuario y la contraseña mediante
//* UsernamePasswordAuthenticationToken.
@Slf4j
public class JwtUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final JwtService jwtService;

    private final ObjectMapper objectMapper;

    public JwtUsernamePasswordAuthenticationFilter(AuthenticationManager manager,
                                                   JwtConfig jwtConfig,
                                                   JwtService jwtService){
        super(new AntPathRequestMatcher(jwtConfig.getUrl(), "POST"));
        setAuthenticationManager(manager);
        this.objectMapper = new ObjectMapper();
        this.jwtService = jwtService;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        log.info("Start attempt to authentication");
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        log.info("End attempt to authentication");

        return getAuthenticationManager()
                .authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword(),
                        Collections.emptyList()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        UserDetailCustom userDetailsCustom = (UserDetailCustom) authentication.getPrincipal();

        String accessToken = jwtService.generateToken(userDetailsCustom);
        String json = HelperUtils.JSON_WRITTER.writeValueAsString(accessToken);
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(json);
        log.info("End success authentication: {}", accessToken);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        BaseResponseDTO responseDTO = new BaseResponseDTO();
        responseDTO.setCode(String.valueOf(HttpStatus.UNAUTHORIZED.value()));
        responseDTO.setMessage(failed.getLocalizedMessage());

        String json = HelperUtils.JSON_WRITTER.writeValueAsString(responseDTO);

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(json);
        return;
    }


}
