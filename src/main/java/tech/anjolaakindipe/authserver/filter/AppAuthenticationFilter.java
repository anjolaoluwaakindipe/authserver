package tech.anjolaakindipe.authserver.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tech.anjolaakindipe.authserver.dto.LoginDto;
import tech.anjolaakindipe.authserver.model.AppUser;
import tech.anjolaakindipe.authserver.model.RefreshToken;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

/**
 * AppAuthenticationFilter
 */
@AllArgsConstructor
@Slf4j

public class AppAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtTokenUtil jwtTokenUtil;

    private final AppUserRepository appUserRepository;

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        log.error("Login Failed");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Map<String, String> errorMessage = new HashMap<>() {
            {
                put("message", "Invalid Username or password");
            }
        };
        new ObjectMapper().writeValue(response.getOutputStream(), errorMessage);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        log.info("Login attempted");
        try {
            LoginDto loginInfo = new ObjectMapper().readValue(request.getInputStream(), LoginDto.class);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    loginInfo.getUsername(), loginInfo.getPassword());
            return this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        log.info("Login succesful");

        
        // check if there is an existing refreshToken from the cookies
        Optional<Cookie> existingRefreshToken = request.getCookies() != null ? Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals("refreshToken")).findFirst() : Optional.empty();

        System.out.println(existingRefreshToken);

        // get userDetails from successful login
        User user = (User) authResult.getPrincipal();

        // generate both access token and refresh token from user details
        String accessToken = jwtTokenUtil.generateAccessToken(user);
        String refreshToken = jwtTokenUtil.generateRefreshToken(user);

        // generate refresh token cookie
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        // refreshTokenCookie.setSecure(true);

        // get existing user from db
        Optional<AppUser> appUser = appUserRepository.findByEmail(user.getUsername());

        // remove
        if (existingRefreshToken.isPresent()) {
            Set<RefreshToken> newRefreshTokenSet = appUser.get().getRefreshTokens().stream()
                    .filter(eachExistingRefreshToken -> !eachExistingRefreshToken
                            .getToken().equals(existingRefreshToken.get().getValue()))
                    .collect(Collectors.toSet());
            appUser.get().setRefreshTokens(newRefreshTokenSet);
        }

        // save refresh token with existing user
        RefreshToken newRefreshToken = RefreshToken.builder().token(refreshToken).build();
        appUser.get().getRefreshTokens().add(newRefreshToken);
        appUserRepository.save(appUser.get());

        // send response
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Map<String, String> tokens = new HashMap<>() {
            {
                put("access_token", accessToken);
                put("refresh_token", refreshToken);
            }
        };

        response.addCookie(refreshTokenCookie);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

}