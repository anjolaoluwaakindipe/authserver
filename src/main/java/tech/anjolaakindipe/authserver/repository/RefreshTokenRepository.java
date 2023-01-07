package tech.anjolaakindipe.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import tech.anjolaakindipe.authserver.model.RefreshToken;

/**
 * RefreshTokenRepository
 */

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

}