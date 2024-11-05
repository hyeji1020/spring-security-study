package com.example.TestSecurity.controller;

import com.example.TestSecurity.request.JoinRequest;
import com.example.TestSecurity.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinP(@RequestBody JoinRequest request) {

        System.out.println(request.getUsername());
        joinService.joinProcess(request);

        return "ok";
    }

}
