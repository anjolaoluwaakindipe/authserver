package tech.anjolaakindipe.authserver.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@RequiredArgsConstructor
public class AppAuthorizationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // TODO Auto-generated method stub
        if(request.getServletPath().equals("/api/auth/login") || request.getServletPath().equals("/api/auth/refresh")){
            filterChain.doFilter(request, response);
            return;
        }

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        try{

            String accessToken = authorizationHeader.substring("Bearer ".length());
            String username = jwtTokenUtil.getUsernameFromAccessToken(accessToken);
            String[] roles = jwtTokenUtil.getRolesFromAccessToken(accessToken);
            for(int i = 0 ; i < roles.length; i ++ ){
                System.out.println(roles[i]);
            }
            Collection<SimpleGrantedAuthority> authorities = Stream.of(roles).map((role)->new SimpleGrantedAuthority(role)).toList();
            // System.out.println(authorities);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response);
        } catch(JWTVerificationException ve){
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String , String> error = new HashMap<>(){{
                put("error_message", ve.getMessage());
            }};
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }

    }
    
}
