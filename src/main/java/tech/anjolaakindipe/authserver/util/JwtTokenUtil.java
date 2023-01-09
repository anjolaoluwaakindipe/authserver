package tech.anjolaakindipe.authserver.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Component
public class JwtTokenUtil implements Serializable {
    private static final long serialVersionUID = -2550185165626007488L;

    private static final int refresh_token_validity = 60 * 60 * 24;
    private static final int access_token_validity = 60 * 10;

    @Value("${secret.token.refresh}")
    private String refreshTokenSecret;

    @Value("${secret.token.access}")
    private String accessTokenSecret;

    @Value("${token.issuer}")
    private String tokenIssuer;

    public String generateAccessToken(UserDetails userDetails) {
        // get roles from userDetails
        List<String> roles = userDetails.getAuthorities().stream().map(authority -> authority.getAuthority()).toList();

        // encode access token
        Algorithm algorithm = Algorithm.HMAC256(this.accessTokenSecret.getBytes());

        // create jwt access token
        return JWT.create().withIssuer(tokenIssuer).withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + access_token_validity * 1000))
                .withIssuedAt(new Date()).withClaim("roles", roles).sign(algorithm);

    }

    public String generateAccessToken(UserDetails userDetails, Map<String, Object> extraClaims) {
        // get roles from userDetails
        List<String> roles = userDetails.getAuthorities().stream().map(authority -> authority.getAuthority()).toList();

        // encode access token
        Algorithm algorithm = Algorithm.HMAC256(this.accessTokenSecret.getBytes());

        // create jwt access token
        return JWT.create().withIssuer(tokenIssuer).withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + access_token_validity * 1000))
                .withIssuedAt(new Date()).withClaim("roles", roles).sign(algorithm);

    }
    public String generateRefreshToken(UserDetails userDetails) {
        // get roles from userDetails
        List<String> roles = userDetails.getAuthorities().stream().map(authority -> authority.getAuthority()).toList();

        // encode refresh token
        Algorithm algorithm = Algorithm.HMAC256(this.refreshTokenSecret.getBytes());

        // create jwt refresh token
        return JWT.create().withIssuer(tokenIssuer).withSubject(userDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + refresh_token_validity * 1000))
                .withIssuedAt(new Date()).withClaim("roles", roles).sign(algorithm);

    }

    private DecodedJWT getDecodedAccessToken(String accessToken){
        // create encoded secret key
        Algorithm algorithm = Algorithm.HMAC256(this.accessTokenSecret.getBytes());
        // create jwt Verifier
        JWTVerifier  jwtVerifier = JWT.require(algorithm).build();
        // verify access token
        DecodedJWT jwt = jwtVerifier.verify(accessToken);
        return jwt;
    }

    private DecodedJWT getDecodedRefreshToken(String refreshToken){
        // create encoded secret key
        Algorithm algorithm = Algorithm.HMAC256(this.refreshTokenSecret.getBytes());
        // create jwt Verifier
        JWTVerifier  jwtVerifier = JWT.require(algorithm).build();
        // verify refresh token
        DecodedJWT jwt = jwtVerifier.verify(refreshToken);
        return jwt;
    }

    public String getUsernameFromAccessToken(String accessToken)throws JWTVerificationException{
        var jwt = getDecodedAccessToken(accessToken);
        return jwt.getSubject();
    }

    public String getUsernameFromRefreshToken(String refreshToken)throws JWTVerificationException{
        var jwt = getDecodedRefreshToken(refreshToken);
        return jwt.getSubject();
    }

    public Date getExpirationDateFromAccessToken(String accessToken)throws JWTVerificationException{
        var jwt = getDecodedAccessToken(accessToken);
        return jwt.getExpiresAt();

    }
    
    public Date getExpirationDateFromRefreshToken(String refreshToken)throws JWTVerificationException{
        var jwt = getDecodedRefreshToken(refreshToken);
        return jwt.getExpiresAt();
    }

    public String[] getRolesFromAccessToken(String accessToken)throws JWTVerificationException{
        var jwt = getDecodedAccessToken(accessToken);
        return jwt.getClaim("roles").asArray(String.class);
    }

    public String[] getRolesFromRefreshToken(String refreshToken)throws JWTVerificationException{
        var jwt = getDecodedRefreshToken(refreshToken);
        return jwt.getClaim("roles").asArray(String.class);
    }

    public boolean isAccessTokenExpired(String accessToken)throws JWTVerificationException{
        var expiredTime = getExpirationDateFromAccessToken(accessToken);
        return expiredTime.before(new Date());
    }

    public boolean isRefreshTokenExpired(String refreshToken)throws JWTVerificationException{
        var expiredTime = getExpirationDateFromRefreshToken(refreshToken);
        return expiredTime.before(new Date());
    }

    public Boolean isAccessTokenValid(String accessToken, UserDetails userDetails)throws JWTVerificationException{
        String username = getUsernameFromAccessToken(accessToken);
        return username.equals(userDetails.getUsername()) && !isAccessTokenExpired(accessToken);
    }

    public Boolean isRefreshTokenValid(String refreshToken, UserDetails userDetails)throws JWTVerificationException{
        String username = getUsernameFromRefreshToken(refreshToken);
        return username.equals(userDetails.getUsername()) && !isRefreshTokenExpired(refreshToken);
    }

}
