package com.example.demo.data.contoller;

import org.springframework.web.bind.annotation.RestController;

import com.example.demo.data.entity.GameRoomEntity;
import com.example.demo.data.entity.UserEntity;
import com.example.demo.data.service.MainService;

import lombok.RequiredArgsConstructor;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MainRestController {
    final private MainService service;

    @GetMapping("/health")
    public String getMethodName(@RequestParam String param) {
        return "ok";
    }

    // USER
    @GetMapping("/user")
    public UserEntity getUser(@RequestParam("user_id") Long user_id) {
        return service.readUser(user_id);
    }

    @PostMapping("/user")
    public void postUser(@RequestBody UserEntity entity) {
        service.createUser(entity);
    }

    @PutMapping("/user/{id}")
    public void updateNickname(@PathVariable("id") Long user_id, @RequestParam("nickname") String nickname) {
        UserEntity entity = service.readUser(user_id);
        entity.setUser_id(user_id);
        entity.setNickname(nickname);
        service.updateUserNickname(entity);
    }

    @DeleteMapping("/user/{id}")
    public void deleteUser(@PathVariable("id") Long user_id) {
        service.deleteUser(user_id);
    }

    // GameRoom
    @PostMapping("/game/room")
    public void postMethodName(@RequestBody GameRoomEntity entity) {
        service.createGR(entity);
    }
}
