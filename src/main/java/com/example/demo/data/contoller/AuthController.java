package com.example.demo.data.contoller;

import com.example.demo.JwtSetting.JwtTokenProvider;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
public class AuthController {
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping("/login")
    public Map<String,String> authenticate(@RequestParam(name = "authToken",required = false) String authToken){
        Map<String,String> map = new HashMap<>();
        if(authToken == null){
            map.put("loginStatus","notAuthenticated");
        }else{
            map.put("loginStatus","authenticated");
        }
        return map;
    }
}
