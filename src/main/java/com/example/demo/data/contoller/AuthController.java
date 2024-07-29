package com.example.demo.data.contoller;

import com.example.demo.JwtSetting.JwtTokenProvider;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
public class AuthController {
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping("/login")
    public String authenticate(){
        return "Login Page";
    }
}
