package tech.anjolaakindipe.authserver.apperrors;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;

import lombok.Data;
import lombok.EqualsAndHashCode;


@Data
@EqualsAndHashCode(callSuper = false)
public class AppError extends Exception {
    private HttpStatus statusCode;
    private Map<String, Object> body = new HashMap<>();

    public AppError(HttpStatus status, Object body) {
        super(body.toString());
        this.statusCode = status;
        this.body.put("message", body );
    }
}