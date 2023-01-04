package tech.anjolaakindipe.authserver.service;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import tech.anjolaakindipe.authserver.model.AppUser;

@SpringBootTest
public class AppUserServiceImplTest {
    @Autowired
    private AppUserService appUserService;




    @BeforeEach
    void setUp(){
    }

    @Test
    void testGetAllUsers() {
        List<AppUser> appUsers = appUserService.getAllUsers();
        assertInstanceOf(new ArrayList<AppUser>().getClass(), appUsers);
    }
}
