package tech.anjolaakindipe.authserver.exceptionhandler;


import java.nio.file.AccessDeniedException;
import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import lombok.extern.slf4j.Slf4j;
import tech.anjolaakindipe.authserver.apperrors.AppError;

@ControllerAdvice
@Slf4j
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler{
    
    @ExceptionHandler(value= {AppError.class})
    protected ResponseEntity<Object> handleAppError(AppError ex,WebRequest request ){
        log.error("Application Error", ex);
        Map<String, Object> body = Map.of("message",ex.getMessage(),"timestamp", ex.getTimestamp().toString() ); 

        return ResponseEntity.status(ex.getStatusCode()).body(body);
    }

    @ExceptionHandler(value = { AccessDeniedException.class })
    public ResponseEntity<Object> handleAccessDeniedException(
            Exception ex, WebRequest request) {
        log.error("Access Denied Error", ex);
        var body = Map.of("message", "Access Denied","timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(value = {RuntimeException.class})
    public ResponseEntity<Object> handleUnexpectedErrors (Exception ex, WebRequest request){
        log.error("Unexpected error", ex);
        var body = Map.of("message", "An Unexpected Error occured", "timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
