package com.example.demo.JwtSetting;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

	private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;  // 30분
	private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;  // 7일

	@Value("${jwt.rsa.secret_key}")
	private String jwtSecretKeyBase64;

	@Value("${jwt.rsa.public_key}")
	private String jwtPublicKeyBase64;

	@Getter
	private Key secretKey;

	@PostConstruct
	protected void init() {
		byte[] decodedKey = Base64.getDecoder().decode(jwtSecretKeyBase64);
		this.secretKey = Keys.hmacShaKeyFor(decodedKey);
	}

	// JWT 토큰 생성
	public String generateToken(Authentication authentication, String userId, String email) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);
		String name = authentication.getName();  // 사용자 이름 가져오기

		return Jwts.builder()
				.setSubject((String) authentication.getPrincipal())  // 사용자 식별자 설정
				.setIssuedAt(now)  // 현재 시간
				.setExpiration(expiryDate)  // 만료 시간 설정
				.claim("userId", userId)  // 추가 클레임
				.claim("email", email)  // 추가 클레임
				.claim("userName", name)  // 추가 클레임
				.signWith(secretKey, SignatureAlgorithm.HS256)  // HMAC-SHA256 서명
				.compact();  // JWT 문자열로 반환
	}

	// JWT 토큰에서 아이디 추출
	public String getUserIdFromJWT(String token) {
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build()
				.parseClaimsJws(token)
				.getBody();

		log.info("id: " + claims.getId());
		log.info("issuer: " + claims.getIssuer());
		log.info("issue: " + claims.getIssuedAt().toString());
		log.info("subject: " + claims.getSubject());
		log.info("audience: " + claims.getAudience());
		log.info("expire: " + claims.getExpiration().toString());
		log.info("userName: " + claims.get("userName"));
		log.info("userId: " + claims.get("userId"));

		return claims.getSubject();
	}

	// JWT 토큰 유효성 검사
	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
			return true;
		} catch (io.jsonwebtoken.security.SecurityException | io.jsonwebtoken.MalformedJwtException e) {
			log.error("잘못된 JWT 서명입니다.", e.getMessage());
		} catch (io.jsonwebtoken.ExpiredJwtException e) {
			log.error("만료된 JWT 토큰입니다.", e.getMessage());
		} catch (io.jsonwebtoken.UnsupportedJwtException e) {
			log.error("지원되지 않는 JWT 토큰입니다.", e.getMessage());
		} catch (IllegalArgumentException e) {
			log.error("JWT 토큰이 잘못되었습니다.", e.getMessage());
		} catch (Exception e) {
			log.error("에러 메세지", e.getMessage());
		}
		return false;
	}
}
