package com.ziminpro.twitter.services;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.List;

@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secretString;

    private Key secretKey;

    @PostConstruct
    public void init() {
        // строку из конфига в криптографический ключ
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
    }

    // generateToken в этом сервисе не нужен

    public String extractUserId(String token) {
        return extractClaims(token).get("id", String.class);
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        return extractClaims(token).get("roles", List.class);
    }

    public boolean validateToken(String token) {
        try {
            // Библиотека проверяет подпись и срок действия при парсинге
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    }
}