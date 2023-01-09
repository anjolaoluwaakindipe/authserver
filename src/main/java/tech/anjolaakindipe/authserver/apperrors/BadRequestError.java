package tech.anjolaakindipe.authserver.apperrors;

import org.springframework.http.HttpStatus;

public class BadRequestError extends AppError {
    public BadRequestError(Object body){
        super(HttpStatus.BAD_REQUEST, body);
    }
}
