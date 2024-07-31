package com.example.demo.JwtSetting;

import com.example.demo.data.service.customOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


@Configuration
//Security filterchain을 구성하기 위한 어노테이션
@EnableWebSecurity
public class SecurityConfiguration {
	private final JwtAuthenticationEntryPoint unauthorizedHandler;
	private final customOAuth2UserService customOAuth2UserService;

	//비밀번호 암호화를 위한 PasswordEncoder
	//복호화가 불가능. match라는 메소드를 이용해서 사용자의 입력값과 DB의 저장값을 비교
	// => true나 false 리턴, match(암호화되지 않은 값, 암호화된 값)
	public SecurityConfiguration(JwtAuthenticationEntryPoint unauthorizedHandler, com.example.demo.data.service.customOAuth2UserService customOAuth2UserService) {
		this.unauthorizedHandler = unauthorizedHandler;
        this.customOAuth2UserService = customOAuth2UserService;
    }

	@Bean
	public static PasswordEncoder passwordEncoder() {
		System.out.println("PasswordEncoder 메서드 호출");
		return new BCryptPasswordEncoder();
	}

	//필터 체인 구현(HttpSecurity 객체 사용)
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    System.out.println("SecurityFilterChain filterChain");
		http.csrf(AbstractHttpConfigurer::disable);

		http.formLogin(formLogin -> {formLogin
				.loginPage("/api/auth/signin")
				.loginProcessingUrl("/auth/loginProc")
				.usernameParameter("email")
				.defaultSuccessUrl("/")
				.failureUrl("/api/auth/signin?error")
				.permitAll();
		});
		http.oauth2Login(oauth2Login -> {
			oauth2Login.loginPage("/api/auth/signin")
					.userInfoEndpoint((userInfoEndpointConfig -> userInfoEndpointConfig.userService(customOAuth2UserService)));
		});
		http.httpBasic((AbstractHttpConfigurer::disable));

		http.authorizeHttpRequests((auth)->{
			auth.requestMatchers("/api/auth/signin").permitAll()
					.requestMatchers("/api/**").permitAll()
					.anyRequest().authenticated();
		});

		http.sessionManagement((auth)->{
			auth.maximumSessions(1)
					.maxSessionsPreventsLogin(false);
		});

		http.logout((auth)->{
			auth.logoutUrl("api/auth/logout")
					.logoutSuccessUrl("api/auth/signin");
		});

		return http.build();
	}

	@Bean
	public WebMvcConfigurer webMvcConfigurer() {
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**")
						.allowedOrigins("http://localhost:3000")
						.allowedMethods("*")
						.allowedHeaders("*");
			}
		};
	}

	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new SimpleUrlAuthenticationSuccessHandler("/"); // 로그인 성공 시 이동할 URL
	}

	@Bean
	public AuthenticationFailureHandler authenticationFailureHandler() {
		return new SimpleUrlAuthenticationFailureHandler("/auth/signin?error"); // 로그인 실패 시 이동할 URL
	}
}