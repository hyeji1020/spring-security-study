package com.example.TestSecurity.controller;


import com.example.TestSecurity.request.JoinRequest;
import com.example.TestSecurity.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @GetMapping("/join")
    public String joinP() {

        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProcess(JoinRequest joinRequest) {

        System.out.println(joinRequest.getUsername());

        joinService.joinProcess(joinRequest);

        return "redirect:/login";
    }
}
