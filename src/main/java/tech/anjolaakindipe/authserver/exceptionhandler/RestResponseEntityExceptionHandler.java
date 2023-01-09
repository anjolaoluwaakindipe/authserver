package tech.anjolaakindipe.authserver.exceptionhandler;


import java.net.http.HttpHeaders;
import java.nio.file.AccessDeniedException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import tech.anjolaakindipe.authserver.apperrors.AppError;

@ControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler{
    
    @ExceptionHandler(value= {AppError.class})
    protected ResponseEntity<Object> handleAppError(AppError ex,WebRequest request ){
        return ResponseEntity.status(ex.getStatusCode()).body(ex.getBody());
    }

    @ExceptionHandler({ AccessDeniedException.class })
    public ResponseEntity<Object> handleAccessDeniedException(
            Exception ex, WebRequest request) {
        var body = Map.of("message", "Access Denied");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }
}
