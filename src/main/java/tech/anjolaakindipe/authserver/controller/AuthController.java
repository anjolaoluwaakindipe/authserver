package tech.anjolaakindipe.authserver.controller;

import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.connector.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tech.anjolaakindipe.authserver.apperrors.AppError;
import tech.anjolaakindipe.authserver.apperrors.BadRequestError;
import tech.anjolaakindipe.authserver.dto.AuthenticationResponse;
import tech.anjolaakindipe.authserver.dto.LoginRequest;
import tech.anjolaakindipe.authserver.dto.RefreshTokenDto;
import tech.anjolaakindipe.authserver.dto.RegisterRequest;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;
import tech.anjolaakindipe.authserver.service.AuthenticationService;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    // private final JwtTokenUtil jwtTokenUtil;
    // private final UserDetailsService userDetailsService;
    private final AuthenticationService authenticationService;
    private final AppUserRepository appUserRepository;

    private void clearCookies(HttpServletResponse response) {

        Cookie clearedRefreshTokenCookie = new Cookie("refreshToken", null);
        clearedRefreshTokenCookie.setMaxAge(0);
        clearedRefreshTokenCookie.setHttpOnly(true);
        response.addCookie(clearedRefreshTokenCookie);
    }

    @GetMapping("/test-error")
    public ResponseEntity<Object> testError() throws BadRequestError {
        if (true) {
            throw new NullPointerException();
        }
        return ResponseEntity.ok("hello");
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request,
            HttpServletResponse response) {
        // delete cookie from response
        this.clearCookies(response);

        // register user and generate access and refresh token
        // update user's refresh token in database
        var tokens = authenticationService.register(request);

        // add refresh token to cookie and return access token as json
        var newRefreshTokenCookie = new Cookie("refreshToken", tokens.getRefreshToken());
        newRefreshTokenCookie.setHttpOnly(true);
        response.addCookie(newRefreshTokenCookie);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest request, HttpServletResponse response,
            @CookieValue(name = "refreshToken", required = false) String refreshTokenCookie) throws AppError {
        // delete cookie from response
        this.clearCookies(response);

        // creates a new access and refresh tokens and updates database
        // on refresh token depending on whether a cookie is present
        var tokens = refreshTokenCookie != null && !refreshTokenCookie.isEmpty()
                ? authenticationService.login(request, refreshTokenCookie)
                : authenticationService.login(request);

        // add refreshToken to cookie and return access token as json
        var newRefreshTokenCookie = new Cookie("refreshToken", tokens.getRefreshToken());
        newRefreshTokenCookie.setHttpOnly(true);
        response.addCookie(newRefreshTokenCookie);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> renewRefreshToken(@CookieValue(name = "refreshToken") String refreshTokenCookie,
            HttpServletResponse response) throws AppError {
        this.clearCookies(response);

        var tokens = authenticationService.refresh(refreshTokenCookie);

        var newRefreshTokenCookie = new Cookie("refreshToken", tokens.getRefreshToken());
        newRefreshTokenCookie.setHttpOnly(true);
        response.addCookie(newRefreshTokenCookie);
        return ResponseEntity.ok(tokens);
    }

    @GetMapping("/logout")
    public ResponseEntity<Object> logout() {
        return ResponseEntity.ok("logged out");
    }
}
