package tech.anjolaakindipe.authserver.service;

import java.util.List;

import org.apache.catalina.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import tech.anjolaakindipe.authserver.model.AppUser;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;

@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {
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
    
}
