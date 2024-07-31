package com.example.demo.data.service.authResponse;

import java.util.Map;

public class kakaoResponse implements OAuth2Response{
    private Map<String, Object> attributes;
    private Map<String, Object> kakaoAccountAttributes;
    private Map<String, Object> profileAttributes;

    public kakaoResponse(Map<String, Object> attributes) {
        this.attributes = attributes;
        this.kakaoAccountAttributes = (Map<String, Object>) attributes.get("kakao_account");
        this.profileAttributes = (Map<String, Object>) attributes.get("properties");

    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getName() {
        return kakaoAccountAttributes.get("name").toString();
    }

    @Override
    public String getEmail() {
        return kakaoAccountAttributes.get("email").toString();
    }

    public String getPhone_number() {
        return kakaoAccountAttributes.get("phone_number").toString();
    }

    public String getAge() {
        return kakaoAccountAttributes.get("age_range").toString();
    }

    public String getGender() {
        return kakaoAccountAttributes.get("gender").toString();
    }

    public String getNickname() {
        return profileAttributes.get("nickname").toString();
    }
}
