package tech.anjolaakindipe.authserver.service;

import org.apache.catalina.Role;

import java.util.List;

import tech.anjolaakindipe.authserver.model.AppUser;


public interface AppUserService {
    AppUser getUserByEmail(String email);
    AppUser saveUserAsUser(String email, String firstname, String lastname, String password);
    AppUser saveUserAsAdmin(String email, String firstname, String lastname, String password);
    Role getUserRole(String email);
    List<AppUser> getAllUsers();
}
