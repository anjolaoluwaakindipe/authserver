package tech.anjolaakindipe.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import lombok.RequiredArgsConstructor;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final AppUserRepository appUserRepository;

    @Bean
    public UserDetailsService userDetailsService(){
        return email -> {
            return appUserRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        };
    }
}
