package tech.anjolaakindipe.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import tech.anjolaakindipe.authserver.model.RefreshToken;

/**
 * RefreshTokenRepository
 */

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

}