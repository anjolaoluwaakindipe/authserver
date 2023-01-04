package tech.anjolaakindipe.authserver.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Value;


@Value 
public class LoginDto {
   private String username;
   private String password; 

   @JsonCreator
   public LoginDto( @JsonProperty("username") String username, @JsonProperty("password") String password){
      this.username = username;
      this.password = password;
   }
}
