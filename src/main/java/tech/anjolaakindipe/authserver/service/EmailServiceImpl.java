package tech.anjolaakindipe.authserver.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    @Autowired
    private JavaMailSender emailSender;

    @Override
    public void sendResetPasswordLink(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom("anjyakindipe");
        message.setTo(email);
        message.setSubject("RESET PASSWORD");
        message.setText(token);
        emailSender.send(message);
    }
    
}
