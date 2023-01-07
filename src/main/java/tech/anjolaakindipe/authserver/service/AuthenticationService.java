package tech.anjolaakindipe.authserver.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tech.anjolaakindipe.authserver.dto.AuthenticationResponse;
import tech.anjolaakindipe.authserver.dto.LoginRequest;
import tech.anjolaakindipe.authserver.dto.RegisterRequest;
import tech.anjolaakindipe.authserver.model.AppUser;
import tech.anjolaakindipe.authserver.model.Role;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        log.info(request.toString());
        var user = AppUser.builder().email(request.getEmail()).firstname(request.getFirstname())
                .lastname(request.getLastname()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER)
                .build();
        repository.save(user);

        var accessToken = jwtTokenUtil.generateAccessToken(user);
        var refreshToken = jwtTokenUtil.generateRefreshToken(user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public AuthenticationResponse login(LoginRequest request) {
        log.info(request.toString());
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        var user = repository.findByEmail(request.getEmail()).orElseThrow();

        var accessToken = jwtTokenUtil.generateAccessToken(user);
        var refreshToken = jwtTokenUtil.generateRefreshToken(user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

}
