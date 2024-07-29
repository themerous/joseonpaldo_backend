package com.example.demo.data.service.authResponse;

import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public class googleResponse implements OAuth2Response{
    private final Map<String,Object> attribute;

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getProviderId() {
        return attribute.get("sub").toString();
    }

    @Override
    public String getEmail() {
        return attribute.get("email").toString();
    }

    @Override
    public String getName() {
        return attribute.get("name").toString();
    }

    public String getGivenName() {
        return attribute.get("given_name").toString();
    }

    public String getFamilyName() {
        return attribute.get("family_name").toString();
    }
}
