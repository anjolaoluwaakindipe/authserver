package tech.anjolaakindipe.authserver.service;

public interface EmailService {
    public void sendResetPasswordLink(String email, String token);
}
