package com.example.demo.data.service.authResponse;

import java.util.Map;

public class naverReponse implements OAuth2Response {
    //로그인 데이터를 담을 Map 선언
    private final Map<String, Object> attribute;

    public naverReponse(Map<String, Object> attribute) {
        this.attribute = (Map<String, Object>) attribute.get("response");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getProviderId() {
        return attribute.get("id").toString();
    }

    @Override
    public String getEmail() {
        return attribute.get("email").toString();
    }

    @Override
    public String getName() {
        return attribute.get("name").toString();
    }

    public String getNickname() {
        return attribute.get("nickname").toString();
    }

    public String getGender() {
        return attribute.get("gender").toString();
    }

    public String getAge() {
        return attribute.get("age").toString();
    }

    public String getMobile() {
        return attribute.get("mobile").toString();
    }
}
