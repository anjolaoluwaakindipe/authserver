package tech.anjolaakindipe.authserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import tech.anjolaakindipe.authserver.filter.AppAuthenticationFilter;
import tech.anjolaakindipe.authserver.filter.AppAuthorizationFilter;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;
import tech.anjolaakindipe.authserver.service.AppUserServiceImpl;
import tech.anjolaakindipe.authserver.util.JwtTokenUtil;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SecurityConfiguration {
    @Autowired
    private AppUserServiceImpl userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private AppUserRepository appUserRepository;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // authenticatiion manager builder
        AuthenticationManagerBuilder authenticationManagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);

        // creating authentication manager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        // creating custome authentication filter
        AppAuthenticationFilter appAuthenticationFilter =  new AppAuthenticationFilter(authenticationManager,  jwtTokenUtil, appUserRepository);

        // creating  custom authorization filter
        AppAuthorizationFilter appAuthorizationFilter = new AppAuthorizationFilter(jwtTokenUtil);

        appAuthenticationFilter.setFilterProcessesUrl("/api/auth/login"); 
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/api/auth/**").permitAll();
        http.authorizeRequests().anyRequest().authenticated();
        http.authenticationManager(authenticationManager);

        http.addFilter(appAuthenticationFilter);
        http.addFilterBefore(appAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl r = new RoleHierarchyImpl();
        r.setHierarchy("ROLE_MANAGER > ROLE_SUPER_USER \n ROLE_SUPER_USER > ROLE_ADMIN \n ROLE_ADMIN > ROLE_USER ");
        return r;
    }

    @Bean 
    public SecurityExpressionHandler<FilterInvocation> expressionHandler(){
        DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy());
        return expressionHandler;
    }
}
