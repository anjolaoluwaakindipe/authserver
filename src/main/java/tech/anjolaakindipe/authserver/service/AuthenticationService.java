package tech.anjolaakindipe.authserver.service;

import tech.anjolaakindipe.authserver.apperrors.AppError;
import tech.anjolaakindipe.authserver.dto.AuthenticationResponse;
import tech.anjolaakindipe.authserver.dto.LoginRequest;
import tech.anjolaakindipe.authserver.dto.RegisterRequest;

public interface AuthenticationService {

    // creates refresh and access tokens and adds the user and generated refresh
    // token to the database
    AuthenticationResponse register(RegisterRequest request);

    // creates refresh and access tokens if user is logging in from a new device
    // and stores the refresh token in the database
    AuthenticationResponse login(LoginRequest request) throws AppError;

    // creates refresh and access token and checks if the refresh token from the
    // cookie is the same in the database,
    // if so the refresh cookie in the database is updated
    AuthenticationResponse login(LoginRequest request, String cookieRefreshToken) throws AppError;

    // logouts out user by deleting any available refreshToken from database
    void logout(String cookieRefreshToken) throws AppError;

    // checks token reuse and refreshes token in database if valid
    // else it deletes the user's tokens
    AuthenticationResponse refresh(String cookieRefreshToken) throws AppError;

    void forgotPassword(String email) throws AppError;

    void changePassword(String password, String token);

}