package tech.anjolaakindipe.authserver.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tech.anjolaakindipe.authserver.dto.AppUserDto;
import tech.anjolaakindipe.authserver.service.AppUserService;

@RestController
@RequestMapping("/api/v1/user")
public class AppUserController {

    @Autowired
    private AppUserService appUserService;

    @GetMapping
    @Secured({"ROLE_SUPER_USER"})
    public ResponseEntity<List<AppUserDto>> getAllUsers() {
        var allUsers = appUserService.getAllUsers();
        var response = allUsers.stream().map(user -> AppUserDto.fromAppUser(user)).toList();
        return ResponseEntity.ok().body(response);
    }

}
