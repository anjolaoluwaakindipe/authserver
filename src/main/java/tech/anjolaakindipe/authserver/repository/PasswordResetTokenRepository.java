package tech.anjolaakindipe.authserver.repository;

import tech.anjolaakindipe.authserver.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    
}
