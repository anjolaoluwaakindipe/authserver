package tech.anjolaakindipe.authserver.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

@SpringBootTest
public class JwtTokenUtilTest {
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
 
    private UserDetails userDetails;

    @BeforeEach
    public void setUp(){
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(){
            {
                add(new SimpleGrantedAuthority("User"));
            }
        };
        userDetails = new User("anjola", "daniel", authorities);
    }

    @Test
    public void shouldGenerateAccessToken(){
        String token = jwtTokenUtil.generateAccessToken(userDetails);
        System.out.println(token);
        assertNotNull(token);
    }
    @Test
    public void shouldGenerateRefreshToken(){
        String token = jwtTokenUtil.generateRefreshToken(userDetails);
        System.out.println(token);
        assertNotNull(token);
    }

    @Test
    public void shouldGiveBackTokenSubjectFromAccessToken(){
        String accessToken = jwtTokenUtil.generateAccessToken(userDetails);
        String username = jwtTokenUtil.getUsernameFromAccessToken(accessToken);
        System.out.println(username);
        assertEquals("anjola", username);
    }

    @Test
    public void shouldGiveBackTokenSubjectFromRefreshToken(){
        String refreshToken = jwtTokenUtil.generateAccessToken(userDetails);
        String username = jwtTokenUtil.getUsernameFromRefreshToken(refreshToken);
        System.out.println(username);
        assertEquals("anjola", username);
    }

    @Test
    public void shouldGiveExpirationDateFromAccessToken(){
        String accessToken = jwtTokenUtil.generateAccessToken(userDetails);
        Date expiresAt = jwtTokenUtil.getExpirationDateFromAccessToken(accessToken);
        System.out.println(expiresAt);
        System.out.println(new Date(System.currentTimeMillis() + 60 * 10 * 1000));
    }

}
