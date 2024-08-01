package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class JoseonpaldoApplication {

	public static void main(String[] args) {
		Dotenv dotenv = Dotenv.load();
		System.setProperty("DB_USERNAME", dotenv.get("DB_USERNAME"));
		System.setProperty("DB_PASSWORD", dotenv.get("DB_PASSWORD"));
		System.setProperty("DB_URL", dotenv.get("DB_URL"));
		System.setProperty("GOOGLE_ID", dotenv.get("GOOGLE_ID"));
		System.setProperty("GOOGLE_PASSWORD", dotenv.get("GOOGLE_PASSWORD"));
		System.setProperty("KAKAO_RESTAPI_KEY", dotenv.get("KAKAO_RESTAPI_KEY"));
		System.setProperty("NAVER_CLIENT_ID", dotenv.get("NAVER_CLIENT_ID"));
		System.setProperty("NAVER_CLIENT_SECRET", dotenv.get("NAVER_CLIENT_SECRET"));
		System.setProperty("JWT_SECRET_KEY", dotenv.get("JWT_SECRET_KEY"));
		System.setProperty("JWT_PUBLIC_KEY", dotenv.get("JWT_PUBLIC_KEY"));
		SpringApplication.run(JoseonpaldoApplication.class, args);
	}
}
