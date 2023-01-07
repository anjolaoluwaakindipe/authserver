package tech.anjolaakindipe.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.AllArgsConstructor;
import tech.anjolaakindipe.authserver.filter.JwtAuthorizationFilter;

@EnableWebSecurity
@Configuration
@AllArgsConstructor
public class SecurityConfiguration {
    
    private final JwtAuthorizationFilter jwtAuthorizationFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // // authenticatiion manager builder
        // AuthenticationManagerBuilder authenticationManagerBuilder = http
        //         .getSharedObject(AuthenticationManagerBuilder.class);
        // authenticationManagerBuilder
        //         .userDetailsService(userDetailsService)
        //         .passwordEncoder(passwordEncoder);

        // // creating authentication manager
        // AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        // // creating custome authentication filter
        // AppAuthenticationFilter appAuthenticationFilter = new AppAuthenticationFilter(authenticationManager,
        //         jwtTokenUtil, appUserRepository);


        // appAuthenticationFilter.setFilterProcessesUrl("/api/auth/login");
        http.csrf().disable()
        .authorizeHttpRequests().requestMatchers("/api/auth/**").permitAll()
        .anyRequest().authenticated().and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        // http.authenticationManager(authenticationManager);
        .authenticationProvider(authenticationProvider)
        // http.addFilter(appAuthenticationFilter);
        .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling();
        return http.build();
    }

    // @Bean
    // public RoleHierarchy roleHierarchy() {
    //     RoleHierarchyImpl r = new RoleHierarchyImpl();
    //     r.setHierarchy("ROLE_MANAGER > ROLE_SUPER_USER \n ROLE_SUPER_USER > ROLE_ADMIN \n ROLE_ADMIN > ROLE_USER ");
    //     return r;
    // }

    // @Bean
    // public SecurityExpressionHandler<FilterInvocation> expressionHandler() {
    //     DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
    //     expressionHandler.setRoleHierarchy(roleHierarchy());
    //     return expressionHandler;
    // }
}
