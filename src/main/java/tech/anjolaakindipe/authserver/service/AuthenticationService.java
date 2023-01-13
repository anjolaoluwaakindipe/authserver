package tech.anjolaakindipe.authserver.service;

import java.util.HashSet;
import java.util.stream.Collectors;

import org.springframework.security.access.method.P;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException.Unauthorized;

import com.auth0.jwt.exceptions.JWTVerificationException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tech.anjolaakindipe.authserver.apperrors.AppError;
import tech.anjolaakindipe.authserver.apperrors.BadRequestError;
import tech.anjolaakindipe.authserver.apperrors.UnauthorizedError;
import tech.anjolaakindipe.authserver.dto.AuthenticationResponse;
import tech.anjolaakindipe.authserver.dto.LoginRequest;
import tech.anjolaakindipe.authserver.dto.RegisterRequest;
import tech.anjolaakindipe.authserver.model.AppUser;
import tech.anjolaakindipe.authserver.model.RefreshToken;
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

    // creates refresh and access tokens and adds the user and generated refresh token
    // to the database 
    public AuthenticationResponse register(RegisterRequest request) {
        log.info(request.toString());
        var user = AppUser.builder().email(request.getEmail()).firstname(request.getFirstname())
                .lastname(request.getLastname()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER)
                .build();
        var accessToken = jwtTokenUtil.generateAccessToken(user);
        var refreshToken = jwtTokenUtil.generateRefreshToken(user);

        var isRefreshTokenAdded = user.getRefreshTokens().add(RefreshToken.builder().token(refreshToken).build());

        if (isRefreshTokenAdded) {
            repository.save(user);
        }

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    // creates refresh and access tokens if user is logging in from a new device
    // and stores the refresh token in the database
    public AuthenticationResponse login(LoginRequest request) throws AppError {
        log.info(request.toString());
        try {
            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (AuthenticationException ex) {
            log.error("Authentication error", ex);
            ;
            throw new UnauthorizedError("Invalid email or password");
        }

        var user = repository.findByEmail(request.getEmail()).orElseThrow();

        var accessToken = jwtTokenUtil.generateAccessToken(user);
        var refreshToken = jwtTokenUtil.generateRefreshToken(user);

        var isRefreshTokenAdded = user.getRefreshTokens().add(RefreshToken.builder().token(refreshToken).build());

        if (isRefreshTokenAdded) {
            repository.save(user);
        }

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    // creates refresh and access token and checks if the refresh token from the cookie is the same
    // in the database, if so the refresh cookie in the database is updated
    public AuthenticationResponse login(LoginRequest request, String cookieRefreshToken) throws AppError {
        log.info(request.toString());
        try {

            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (AuthenticationException ex) {
            log.error("Authentication error", ex);
            throw new UnauthorizedError("Invalid email or password");
        }

        var user = repository.findByEmail(request.getEmail()).orElseThrow();

        var accessToken = jwtTokenUtil.generateAccessToken(user);
        var refreshToken = jwtTokenUtil.generateRefreshToken(user);

        // find if user has a refreshToken that equals to existingRefreshToken
        var existingRefreshToken = user.getRefreshTokens().stream()
                .filter(existingToken -> existingToken.getToken().equals(cookieRefreshToken)).findFirst();

        if (existingRefreshToken.isPresent()) {
            existingRefreshToken.get().setToken(refreshToken);
        } else {
            user.getRefreshTokens().add(RefreshToken.builder().token(refreshToken).build());

        }

        repository.save(user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    // logouts out user by delete refreshToken from database
    public void logout(String cookieRefreshToken) throws AppError{

    }


    // checks token reuse and refreshes token in database if valid
    // else it deletes the user's tokens
    public AuthenticationResponse refresh(String cookieRefreshToken) throws AppError {
        try {
            var appUserOptional = repository.findDistinctByRefreshTokensToken(cookieRefreshToken);

            // detected refresh token reuse
            if (appUserOptional.isEmpty()) {

                var tokenEmail = jwtTokenUtil.getUsernameFromRefreshToken(cookieRefreshToken);

                // if email is present
                if (tokenEmail != null && !jwtTokenUtil.isAccessTokenExpired(cookieRefreshToken)) {

                    var hackedUserOptional = repository.findByEmail(tokenEmail);
                    if (hackedUserOptional.isPresent()) {
                        var hackedUser = hackedUserOptional.get();
                        hackedUser.setRefreshTokens(new HashSet<RefreshToken>());

                        repository.save(hackedUser);
                    }

                }
                throw new BadRequestError("Invalid Refresh Token");

            }

            var appUser = appUserOptional.get();

            // removes refresh token that is already there
            var databaseRefreshTokenOptional = appUser.getRefreshTokens().stream()
                    .filter(token -> token.getToken().equals(cookieRefreshToken)).findFirst();

            if (databaseRefreshTokenOptional.isEmpty()) {
                throw new BadRequestError("Invalid RefreshToken");
            }

            var databaseRefreshToken = databaseRefreshTokenOptional.get();

            // sends a warning if refresh token from cookie is expired
            if (jwtTokenUtil.isRefreshTokenExpired(cookieRefreshToken)) {
                appUser.getRefreshTokens().remove(databaseRefreshToken);
                repository.save(appUser);
                throw new BadRequestError("Refresh token has expired");
            }

            var accessToken = jwtTokenUtil.generateAccessToken(appUser);
            var refreshToken = jwtTokenUtil.generateRefreshToken(appUser);

            // adds generated refresh token to database
            databaseRefreshToken.setToken(refreshToken);
            repository.save(appUser);

            return new AuthenticationResponse(accessToken, refreshToken);

        } catch (JWTVerificationException ex) {
            log.error("JWT Verification Error", ex);
            throw new BadRequestError("Invalid Refresh Token");
        }
    }

}
