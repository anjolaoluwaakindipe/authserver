package tech.anjolaakindipe.authserver.apperrors;

import org.springframework.http.HttpStatus;

public class ValidationError extends AppError {
    public ValidationError(Object body){
        super(HttpStatus.BAD_REQUEST, body);
    }
}
