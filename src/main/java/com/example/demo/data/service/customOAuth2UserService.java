package com.example.demo.data.service;

import com.example.demo.data.entity.UserEntity;
import com.example.demo.data.repository.UserRepositoryImpl;
import com.example.demo.data.service.authResponse.OAuth2Response;
import com.example.demo.data.service.authResponse.googleResponse;
import com.example.demo.data.service.authResponse.kakaoResponse;
import com.example.demo.data.service.authResponse.naverReponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class customOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepositoryImpl userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        UserEntity userEntity=null;

        String idProvider=oAuth2UserRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response=null;

        switch (idProvider) {
            case "google":{
                oAuth2Response = new googleResponse(oAuth2User.getAttributes());
                userEntity = new UserEntity().builder()
                        .email(oAuth2Response.getEmail())
                        .social_provider(oAuth2Response.getProvider())
                        .nickname(oAuth2Response.getName())
                        .build();
            }
            case "naver":{
                oAuth2Response=new naverReponse(oAuth2User.getAttributes());
                userEntity = new UserEntity().builder()
                        .email(oAuth2Response.getEmail())
                        .social_provider(oAuth2Response.getProvider())
                        .nickname(oAuth2Response.getName())
                        .build();
            }
            case "kakao":{
                oAuth2Response=new kakaoResponse(oAuth2User.getAttributes());
                userEntity = new UserEntity().builder()
                        .email(oAuth2Response.getEmail())
                        .social_provider(oAuth2Response.getProvider())
                        .nickname(oAuth2Response.getName())
                        .build();
            }
            default:{
                return null;
            }
        }


    }
}
