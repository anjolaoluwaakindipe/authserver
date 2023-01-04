package tech.anjolaakindipe.authserver.util;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AppPasswordEncoder {

    @Bean
    static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
