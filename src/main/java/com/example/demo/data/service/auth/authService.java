package com.example.demo.data.service.auth;

import com.example.demo.JwtSetting.JwtTokenProvider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

@Service
@RequiredArgsConstructor
public class authService extends DefaultOAuth2UserService {

    private final WebClient.Builder webClientBuilder;
    private final WebClient.Builder webClient;
    private final JwtTokenProvider jwtTokenProvider;  // JwtTokenProvider 인스턴스 추가
    private static String token;
    ObjectMapper objectMapper = new ObjectMapper();

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;
    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;
    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;
    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String naverClientSecret;
    private String redirectUri = "http://localhost:8080/api/auth/signin/callback/";

    public String sendPostRequest(String provider, String code) {
        WebClient webClient = webClientBuilder.build();
        String url = "";
        Mono<String> response = null;
        CountDownLatch latch = new CountDownLatch(1);  // 비동기 결과 대기를 위한 Latch

        switch (provider) {
            case "google": {
                url = "https://oauth2.googleapis.com/token";
                response = webClient.post()
                        .uri(url)
                        .header("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
                        .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                                .with("client_id", googleClientId)
                                .with("client_secret", googleClientSecret)
                                .with("redirect_uri", redirectUri + "google")
                                .with("code", code))
                        .retrieve()
                        .bodyToMono(String.class);

                response.subscribe(jsonResponse -> {
                    try {
                        JsonNode jsonNode = objectMapper.readTree(jsonResponse);
                        String idToken = jsonNode.get("id_token").asText();

                        // id_token 파싱 및 검증
                        Claims claims = Jwts.parserBuilder()
                                .setSigningKey(jwtTokenProvider.getSecretKey())
                                .build()
                                .parseClaimsJws(idToken)
                                .getBody();

                        // 사용자 정보 추출
                        String username = claims.getSubject();
                        String userEmail = claims.get("email", String.class);
                        String userId = claims.get("nickname", String.class);

                        // UserDetails 생성
                        UserDetails userDetails = User.builder()
                                .username(username)
                                .password("")  // 비밀번호는 빈 값으로 설정
                                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")))
                                .build();

                        // Authentication 객체 생성
                        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                        // JWT 토큰 생성
                        token = jwtTokenProvider.generateToken(authentication, userId, userEmail);
                        System.out.println("JWT Token: " + token);

                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        latch.countDown();  // Latch를 해제
                    }
                });

                break;
            }
            case "kakao": {
                url = "https://kauth.kakao.com/oauth/token";
                response = webClient.post()
                        .uri(url)
                        .header("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
                        .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                                .with("client_id", kakaoClientId)
                                .with("redirect_uri", redirectUri + "kakao")
                                .with("code", code))
                        .retrieve()
                        .bodyToMono(String.class);

                response.subscribe(System.out::println);
                break;
            }
            case "naver": {
                url = "https://nid.naver.com/oauth2.0/token";
                response = webClient.post()
                        .uri(url)
                        .header("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
                        .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                                .with("client_id", naverClientId)
                                .with("client_secret", naverClientSecret)
                                .with("redirect_uri", redirectUri + "naver")
                                .with("code", code))
                        .retrieve()
                        .bodyToMono(String.class);

                response.subscribe(System.out::println);
                break;
            }
            default:
                throw new IllegalStateException("Unexpected value: " + provider);
        }

        try {
            latch.await();  // 비동기 결과 대기
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return token;
    }
}