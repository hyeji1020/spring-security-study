package com.example.TestSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

// SecurityFilterChain 설정을 진행 하는 클래스
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 순서대로 실행하기 때문에 주의
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")   // 로그인 페이지 경로 지정
                        .loginProcessingUrl("/loginProc")       // 로그인 처리 URL 지정
                        .permitAll()                            // 로그인 페이지는 인증 없이 접근 가능하도록 설정
                );

        http
                .csrf((auth) -> auth.disable());

        return http.build();
    }

}
