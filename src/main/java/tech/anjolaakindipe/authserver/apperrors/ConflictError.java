package tech.anjolaakindipe.authserver.apperrors;

import org.springframework.http.HttpStatus;

public class ConflictError extends AppError{
    public ConflictError(Object body){
        super(HttpStatus.CONFLICT, body);
    }
}