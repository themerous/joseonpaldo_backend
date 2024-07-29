package com.example.demo.JwtSetting;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
	private JwtAuthenticationEntryPoint unauthorizedHandler;
	//비밀번호 암호화를 위한 PasswordEncoder
	//복호화가 불가능. match라는 메소드를 이용해서 사용자의 입력값과 DB의 저장값을 비교
	// => true나 false 리턴, match(암호화되지 않은 값, 암호화된 값)
	public SecurityConfiguration(JwtAuthenticationEntryPoint unauthorizedHandler) {
		this.unauthorizedHandler = unauthorizedHandler;
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
		http
		//csrf 공격에 대한 옵션 꺼두기
		.csrf(AbstractHttpConfigurer::disable)
				.cors(cors -> cors
						.configurationSource(request -> { // React 애플리케이션의 URL
									// 모든 HTTP 메소드 허용
									CorsConfiguration corsConfiguration = new CorsConfiguration();
							corsConfiguration.addAllowedOrigin("http://localhost:3000");
							corsConfiguration.addAllowedMethod("*");
							corsConfiguration.addAllowedHeader("*");
							return corsConfiguration;
								}
						)
				)
		.addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
		//요청 주소에 대한 권한 설정
		.authorizeHttpRequests((authorizeRequests) -> authorizeRequests
				.requestMatchers("/auth/login").permitAll()
				.requestMatchers("/").authenticated()
				.anyRequest().authenticated())
				.formLogin(formLogin -> formLogin
						.loginProcessingUrl("/auth/login") // 로그인 처리 엔드포인트
						.successHandler(authenticationSuccessHandler()) // 로그인 성공 처리 핸들러
						.failureHandler(authenticationFailureHandler()) // 로그인 실패 처리 핸들러
				)
				.exceptionHandling(exceptionHandling->exceptionHandling
						.authenticationEntryPoint(unauthorizedHandler))//인증되지 않은 요청에 대한 핸들러 설정
				.headers(headers ->
					headers.frameOptions().disable()
				)
        .csrf(csrf -> csrf
        		.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")));
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
		return new SimpleUrlAuthenticationFailureHandler("/auth/login?error"); // 로그인 실패 시 이동할 URL
	}
}