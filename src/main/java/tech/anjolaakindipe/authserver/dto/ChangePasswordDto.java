package tech.anjolaakindipe.authserver.dto;

public record ChangePasswordDto(String password, String confirmPassword, String token) {
    
}
