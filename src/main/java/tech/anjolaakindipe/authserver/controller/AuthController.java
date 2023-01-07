package tech.anjolaakindipe.authserver.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import tech.anjolaakindipe.authserver.dto.AuthenticationResponse;
import tech.anjolaakindipe.authserver.dto.LoginRequest;
import tech.anjolaakindipe.authserver.dto.RefreshTokenDto;
import tech.anjolaakindipe.authserver.dto.RegisterRequest;
import tech.anjolaakindipe.authserver.service.AuthenticationService;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService userDetailsService;
    private final AuthenticationService authenticationService;



    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        var tokens = authenticationService.login(request);
        response.addCookie(new Cookie("refreshToken", tokens.getRefreshToken()));
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> renewRefreshToken(@RequestBody RefreshTokenDto refreshTokenDto) {
        try {
            String username = jwtTokenUtil.getUsernameFromRefreshToken(refreshTokenDto.refreshToken());
            UserDetails user = userDetailsService.loadUserByUsername(username);
            String accessToken = jwtTokenUtil.generateAccessToken(user);
            String refreshToken = jwtTokenUtil.generateRefreshToken(user);
            Map<String, String> tokens = new HashMap<>() {
                {
                    put("access_token", accessToken);
                    put("refresh_token", refreshToken);
                }
            };
            return ResponseEntity.ok(tokens);
        } catch (Exception e) {
            Map<String, String> error_messag = new HashMap<>() {
                {
                    put("error", e.getMessage());
                }
            };
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error_messag);
        }

    }
}
