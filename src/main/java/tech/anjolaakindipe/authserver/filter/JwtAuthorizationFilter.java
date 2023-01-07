package tech.anjolaakindipe.authserver.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@RequiredArgsConstructor
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // check if request path is an to allowed path
        if (request.getServletPath().equals("/api/auth/login")
                || request.getServletPath().equals("/api/auth/refresh")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        final String jwtAccessToken;
        final String userEmail;

        // check if jwt is present in the Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // get accesstoken from Authorization header
            jwtAccessToken = authHeader.substring("Bearer ".length());

            // extract user email from accessToken
            userEmail = jwtTokenUtil.getUsernameFromAccessToken(jwtAccessToken);

            // if user email is valid and there is no context in the SecurityContextHolder
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // find email in database and return the user as a userDetail
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                if (jwtTokenUtil.isAccessTokenValid(jwtAccessToken, userDetails)) {
                    // System.out.println(authorities);
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null, userDetails.getAuthorities());

                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }

            filterChain.doFilter(request, response);
            return;
        } catch (JWTVerificationException ve) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, String> error = new HashMap<>() {
                {
                    put("error_message", ve.getMessage());
                }
            };
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }

    }

}
