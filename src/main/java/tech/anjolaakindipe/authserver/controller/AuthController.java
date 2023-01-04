package tech.anjolaakindipe.authserver.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;
import tech.anjolaakindipe.authserver.dto.RefreshTokenDto;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private UserDetailsService userDetailsService;

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
