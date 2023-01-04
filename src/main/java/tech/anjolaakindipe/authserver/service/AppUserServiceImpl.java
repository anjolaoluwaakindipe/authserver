package tech.anjolaakindipe.authserver.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import org.apache.catalina.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import tech.anjolaakindipe.authserver.model.AppUser;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;

@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService, UserDetailsService {
    @Autowired
    private AppUserRepository appUserRepository;

    @Override
    public AppUser getUserByEmail(String email) {
        // TODO Auto-generated method stub
        
        return null;
    }

    @Override
    public AppUser saveUserAsUser(String email, String firstname, String lastname, String password) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public AppUser saveUserAsAdmin(String email, String firstname, String lastname, String password) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Role getUserRole(String email) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<AppUser> getAllUsers() {
        // TODO Auto-generated method stub
        List<AppUser> appUser = appUserRepository.findAll();
        return appUser;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // TODO Auto-generated method stub

        Optional<AppUser> optionalUser =  appUserRepository.findByEmail(email);
        AppUser existingUser = optionalUser.orElseThrow(()-> new UsernameNotFoundException("Invalid User name of password"));

        Collection<SimpleGrantedAuthority> authorities = existingUser.getRoles().stream().map((role)-> new SimpleGrantedAuthority(role.getName())).toList();

        UserDetails userDetails =  new User(existingUser.getEmail(), existingUser.getPassword(), authorities);

        return userDetails;
    }
    
}
