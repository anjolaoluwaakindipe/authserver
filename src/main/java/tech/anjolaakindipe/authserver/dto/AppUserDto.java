package tech.anjolaakindipe.authserver.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import tech.anjolaakindipe.authserver.model.AppUser;

@Data
@AllArgsConstructor
@Builder
public class AppUserDto {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;


    static public AppUserDto fromAppUser(AppUser appUser){
        return AppUserDto.builder().email(appUser.getEmail()).firstName(appUser.getFirstname()).lastName(appUser.getLastname()).id(appUser.getId()).build();
    }
}
