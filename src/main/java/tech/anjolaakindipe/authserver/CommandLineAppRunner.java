package tech.anjolaakindipe.authserver;

import java.util.Optional;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jakarta.transaction.Transactional;
import tech.anjolaakindipe.authserver.model.AppUser;
import tech.anjolaakindipe.authserver.model.Role;
import tech.anjolaakindipe.authserver.repository.AppUserRepository;

@Component
public class CommandLineAppRunner implements CommandLineRunner {

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private PasswordEncoder bycryptEncoder;

    @Override
    @Transactional
    public void run(String... args) throws Exception {


        AppUser appUser = AppUser.builder().email("anjyakindipe@gmail.com").firstname("Anjola").lastname("Akindipe")
                .password("hello123").build();
        appUser.setPassword(bycryptEncoder.encode(appUser.getPassword()));
        appUser.setRole(Role.ADMIN);;

        Optional<AppUser> optionalUser = appUserRepository.findByEmail(appUser.getEmail());

        if (optionalUser.isPresent()) {
            System.out.println(optionalUser.get());
            return;
        }

        appUserRepository.save(appUser);
    }

}
