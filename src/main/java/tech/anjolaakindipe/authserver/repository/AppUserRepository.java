package tech.anjolaakindipe.authserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import tech.anjolaakindipe.authserver.model.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
    Optional<AppUser> findDistinctByRefreshTokensToken(String token);
}
