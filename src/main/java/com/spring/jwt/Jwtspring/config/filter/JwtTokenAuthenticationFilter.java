package com.spring.jwt.Jwtspring.config.filter;

import com.spring.jwt.Jwtspring.jwt.JwtConfig;
import com.spring.jwt.Jwtspring.jwt.JwtService;
import com.spring.jwt.Jwtspring.utilities.BaseResponseDTO;
import com.spring.jwt.Jwtspring.utilities.HelperUtils;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
//* este filtro intercepta todas las solicitudes HTTP entrantes y verifica si la solicitud tiene un token JWT
//* válido en la cabecera "Authorization". Si se encuentra un token válido, se crea un objeto de autenticación y
//* se establece en el contexto de seguridad de Spring. Si no se encuentra un token o el token no es válido, se
//* devuelve una respuesta de error HTTP no autorizada.
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;

    private final JwtService jwtService;

    //* todo entra por esta peticion
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //* obtenemos el token del header
        String accessToken = request.getHeader(jwtConfig.getHeader());

        log.info("Start do filter once per request, {}", request.getRequestURI());
        //* validamos que el token sea valido
        if (!ObjectUtils.isEmpty(accessToken) && accessToken.startsWith(jwtConfig.getPrefix() + " ")) {
            accessToken = accessToken.substring((jwtConfig.getPrefix() + " ").length());

            try {
                if (jwtService.isValidToken(accessToken)) {
                    Claims claims = jwtService.extractClaims(accessToken);

                    String username = claims.getSubject();

                    List<String> authorities = claims.get("authorities", List.class);

                    if (!ObjectUtils.isEmpty(username)) {
                        //* creamos un objeto de authenticacion que enviaremos al contexto
                        UsernamePasswordAuthenticationToken auth =
                                new UsernamePasswordAuthenticationToken(
                                        username,
                                        null,
                                        authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }
                }
            } catch (Exception e) {
                log.error("Error on filter once per request, path {}, error: {}", request.getRequestURI(), e.getMessage());
                BaseResponseDTO responseDTO = new BaseResponseDTO();
                responseDTO.setCode(String.valueOf(HttpStatus.UNAUTHORIZED.value()));
                responseDTO.setMessage(e.getLocalizedMessage());

                String json = HelperUtils.JSON_WRITTER.writeValueAsString(responseDTO);

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json; charset=UTF-8");
                response.getWriter().write(json);
                return;

            }
        }
        //* pasamos la peticion
        log.info("end do filter: {}", request.getRequestURI());
        filterChain.doFilter(request, response);

    }
}
