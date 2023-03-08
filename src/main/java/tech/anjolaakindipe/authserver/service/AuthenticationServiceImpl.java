package tech.anjolaakindipe.authserver.service;

import java.util.HashSet;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
import tech.anjolaakindipe.authserver.model.PasswordResetToken;
import tech.anjolaakindipe.authserver.model.RefreshToken;
import tech.anjolaakindipe.authserver.model.Role;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;
import tech.anjolaakindipe.authserver.repository.PasswordResetTokenRepository;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    // creates refresh and access tokens and adds the user and generated refresh
    // token to the database
    @Override
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
    @Override
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

    // creates refresh and access token and checks if the refresh token from the
    // cookie is the same in the database,
    // if so the refresh cookie in the database is updated
    @Override
    public AuthenticationResponse login(LoginRequest request, String cookieRefreshToken) throws AppError {
        // validate if login info
        try {

            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (AuthenticationException ex) {
            log.error("Authentication error", ex);
            throw new UnauthorizedError("Invalid email or password");
        }

        // find user by email login is okay
        var user = repository.findByEmail(request.getEmail()).orElseThrow();

        // generate access and refresh token
        var accessToken = jwtTokenUtil.generateAccessToken(user);
        var refreshToken = jwtTokenUtil.generateRefreshToken(user);

        // find if user has a refreshToken in the database that
        // matches the existingRefreshToken in the cookie
        var existingRefreshToken = user.getRefreshTokens().stream()
                .filter(existingToken -> existingToken.getToken().equals(cookieRefreshToken)).findFirst();

        // if there is already an existing refresh token that matches the one in the
        // database
        // change it to the generated one
        if (existingRefreshToken.isPresent()) {
            existingRefreshToken.get().setToken(refreshToken);
        } else {
            user.getRefreshTokens().add(RefreshToken.builder().token(refreshToken).build());

        }

        // save changes
        repository.save(user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    // logouts out user by deleting any available refreshToken from database
    @Override
    public void logout(String cookieRefreshToken) throws AppError {

        // find a user that has a refresh token that matches
        // cookieRefreshToken
        var appUserOptional = repository.findDistinctByRefreshTokensToken(cookieRefreshToken);

        if (appUserOptional.isEmpty()) {
            return;
        }

        AppUser appUser = appUserOptional.get();

        // get refresh token from the database that matches the cookie
        // refresh token
        var databaseRefreshTokenOptional = appUser.getRefreshTokens().stream()
                .filter(token -> token.getToken().equals(cookieRefreshToken)).findFirst();

        if (databaseRefreshTokenOptional.isEmpty()) {
            throw new BadRequestError("Invalid RefreshToken");
        }

        RefreshToken databaseRefreshToken = databaseRefreshTokenOptional.get();
        appUser.getRefreshTokens().remove(databaseRefreshToken);
        repository.save(appUser);

    }

    // checks token reuse and refreshes token in database if valid
    // else it deletes the user's tokens
    @Override
    public AuthenticationResponse refresh(String cookieRefreshToken) throws AppError {
        try {

            // find a user that has a refresh token that matches
            // cookieRefreshToken
            var appUserOptional = repository.findDistinctByRefreshTokensToken(cookieRefreshToken);

            // detected refresh token reuse
            // if there is no user with that refresh token
            if (appUserOptional.isEmpty()) {

                // get user that is being hacked from the cookie Refresh token
                var tokenEmail = jwtTokenUtil.getUsernameFromRefreshToken(cookieRefreshToken);

                // if email is present
                if (tokenEmail != null && !jwtTokenUtil.isAccessTokenExpired(cookieRefreshToken)) {
                    // find user
                    var hackedUserOptional = repository.findByEmail(tokenEmail);

                    // if user is present
                    if (hackedUserOptional.isPresent()) {

                        // log out user from all devices
                        // by deleting all his refresh tokens
                        var hackedUser = hackedUserOptional.get();
                        hackedUser.setRefreshTokens(new HashSet<RefreshToken>());

                        repository.save(hackedUser);
                    }

                }
                throw new BadRequestError("Invalid Refresh Token");

            }

            // get the user if there is a match
            var appUser = appUserOptional.get();

            // get refresh token from the database that matches the cookie
            // refresh token
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

            // generate refresh token and access token
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

    @Override
    public void forgotPassword(String email) throws AppError {
        // check if user exist by email
        Optional<AppUser> user = repository.findByEmail(email);
        if (user.isEmpty()) {
            throw new AppError(HttpStatus.NOT_FOUND, "Email not found");
        }

        // generate a token from the existing user
        String token = jwtTokenUtil.generateResetPasswordToken(user.get());

        // create a password reset entity
        PasswordResetToken passwordResetToken = PasswordResetToken.builder().token(token).appUser(user.get()).build();

        // save password reset token to database
        passwordResetTokenRepository.save(passwordResetToken);

        // send email to user's email
        emailService.sendResetPasswordLink(email, token);

    }

    @Override
    public void changePassword(String password, String token) {
        
    }

}
