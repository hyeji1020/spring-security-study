package com.example.TestSecurity.service;

import com.example.TestSecurity.entity.UserEntity;
import com.example.TestSecurity.repository.UserRepository;
import com.example.TestSecurity.request.JoinRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinRequest joinRequest) {
        //username 중복 검사
        boolean isUser = userRepository.existsByUsername(joinRequest.getUsername());
        if (isUser) {
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(joinRequest.getUsername());
        data.setPassword(bCryptPasswordEncoder.encode(joinRequest.getPassword()));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
