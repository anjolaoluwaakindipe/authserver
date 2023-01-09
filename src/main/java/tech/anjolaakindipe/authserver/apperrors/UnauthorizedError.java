package tech.anjolaakindipe.authserver.apperrors;

import org.springframework.http.HttpStatus;

public class UnauthorizedError extends AppError {
    public UnauthorizedError(Object body){
        super(HttpStatus.UNAUTHORIZED, body);
    }
}
