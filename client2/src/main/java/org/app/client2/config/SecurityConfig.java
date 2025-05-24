package org.app.client2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                    .authorizeHttpRequests(auth -> auth
                    .anyRequest().authenticated()
                    )
                    .oauth2Login(oauth2 -> oauth2
                            .defaultSuccessUrl("/token", true)
                            .userInfoEndpoint(userInfo -> userInfo.userService(dummyUserService()))
                    );
            return http.build();
        }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> dummyUserService() {
        return userRequest -> {
            String clientId = userRequest.getClientRegistration().getClientId();
            return new DefaultOAuth2User(
                    List.of(new SimpleGrantedAuthority("ROLE_USER")),
                    Map.of("name", clientId),
                    "name"
            );
        };
    }


}