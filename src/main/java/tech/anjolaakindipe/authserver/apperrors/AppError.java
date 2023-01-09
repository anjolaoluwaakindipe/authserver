package tech.anjolaakindipe.authserver.apperrors;

import java.time.Instant;
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
    private Instant timestamp = Instant.now();

    public AppError(HttpStatus status, Object body) {
        super(body.toString());
        this.statusCode = status;
        this.body.put("message", body );
    }
}