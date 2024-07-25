package com.example.demo.JwtSetting;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
//Security filterchain을 구성하기 위한 어노테이션
@EnableWebSecurity
public class SecurityConfiguration {
	private JwtAuthenticationEntryPoint unauthorizedHandler;
	//비밀번호 암호화를 위한 PasswordEncoder
	//복호화가 불가능. match라는 메소드를 이용해서 사용자의 입력값과 DB의 저장값을 비교
	// => true나 false 리턴, match(암호화되지 않은 값, 암호화된 값)
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
		.addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
		//요청 주소에 대한 권한 설정
		.authorizeHttpRequests((authorizeRequests) -> {
			//'/'요청은 모든 사용자가 이용가능
			authorizeRequests
			.requestMatchers("/").permitAll()
			.requestMatchers("/favicon.ico").permitAll()
			//.requestMatchers("/h2-console/**").permitAll()	
			.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
			//css, js, images, upload 같은 정적 리소스들도 권한처리 필수
			.requestMatchers("/css/**").permitAll()
			.requestMatchers("/js/**").permitAll()
			.requestMatchers("/upload/**").permitAll()
			.requestMatchers("/images/**").permitAll()
			//게시판 기능은 권한을 가지고 있는 사용자만 사용가능
			//.requestMatchers("/board/**").hasAnyRole("ADMIN", "USER")
			//관리자 페이지는 관리자만 사용가능
			//.requestMatchers("/admin/**").hasRole("ADMIN")
			//회원가입, 로그인, 아이디중복체크 등 요청은 모든 사용자가 사용가능
			//.requestMatchers("/user/join").permitAll()
			.requestMatchers("/auth/login").permitAll()
					.requestMatchers("/boot/member/**").permitAll()
					.requestMatchers("/boot/board/**").permitAll()
					.requestMatchers("/mycar/**").permitAll()
		//이외의 요청은 인증된 사용자만 사용자만 사용가능
			.anyRequest().authenticated();					
		})
		
		.headers(headers -> headers.frameOptions().disable())
        .csrf(csrf -> csrf
        		.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")));
 		
		return http.build();
	}
}