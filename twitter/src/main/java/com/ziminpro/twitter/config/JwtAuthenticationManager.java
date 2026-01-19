package com.ziminpro.twitter.config;

import com.ziminpro.twitter.services.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    @Autowired
    private JwtService jwtService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();

        try {
            if (jwtService.validateToken(authToken)) {
                String username = jwtService.extractUsername(authToken);
                List<String> roles = jwtService.extractRoles(authToken);

                // Преобразуем роль строкой в объект authorities
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // Создаем объект аутентификации
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username,
                        authToken,
                        authorities
                );

                return Mono.just(auth);
            }
        } catch (Exception e) {
            return Mono.empty();
        }

        return Mono.empty();
    }
}