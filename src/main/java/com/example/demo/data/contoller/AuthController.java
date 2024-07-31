package com.example.demo.data.contoller;

import com.example.demo.JwtSetting.JwtTokenProvider;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/api/auth")
@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
public class AuthController {
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping("/signin")
    public String authenticate(@RequestParam(name = "authToken",required = false) String authToken){
        Map<String,String> map = new HashMap<>();

        if(authToken == null){
            map.put("loginStatus","notAuthenticated");
        }else{
            map.put("loginStatus","authenticated");
        }
        return "redirect:http://localhost:3000/";
    }

    @ResponseBody
    @GetMapping("/signin/callback/{provider}")
    public String authenticateCallback(@RequestParam(name = "code") String code,
                                       @PathVariable(name = "provider") String provider
                                                   ){
        Map<String,String> map = new HashMap<>();

        return "map";
    }
}
