package org.app.client2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

@Controller
public class TokenController {

    private final WebClient webClient;

    public TokenController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/token";
    }



    @GetMapping("/token")
    public String tokenPage(
            @RegisteredOAuth2AuthorizedClient("auth-server") OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User oauth2User,
            Model model) {

        model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
        if (authorizedClient.getRefreshToken() != null) {
            model.addAttribute("refreshToken", authorizedClient.getRefreshToken().getTokenValue());
        }

        model.addAttribute("principalName", oauth2User.getName());
        return "token";
    }

    @GetMapping("/call-resource")
    public String callResource(@RegisteredOAuth2AuthorizedClient("auth-server") OAuth2AuthorizedClient authorizedClient,
                               Model model) {
        String response = webClient.get()
                .uri("http://localhost:8081/api/hello")
                .headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("resourceResponse", response);
        return "token";
    }
}
