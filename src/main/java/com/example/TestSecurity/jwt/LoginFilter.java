package com.example.TestSecurity.jwt;

import com.example.TestSecurity.response.CustomUserDetails;
import com.example.TestSecurity.jwt.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    /**
     * 사용자가 로그인 요청 시 호출되는 메서드입니다.
     * 여기서 사용자로부터 `username`과 `password`를 추출하고, 이를 `AuthenticationManager`로 전달하여 인증을 시도합니다.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // Spring Security에서 username과 password 검증을 위해 AuthenticationToken에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // 토큰에 담은 인증 정보를 AuthenticationManager로 전달하여 인증 시도
        return authenticationManager.authenticate(authToken);
    }

    /**
     * 로그인 성공 시 호출되는 메서드입니다.
     * 여기서 JWT 토큰을 생성하고, 응답 헤더에 추가하거나 쿠키에 추가하여 클라이언트에게 전달합니다.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // 인증된 사용자 정보 추출
        String username = authentication.getName();

        // 사용자의 권한 정보 추출 (예: ROLE_USER, ROLE_ADMIN 등)
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // Access Token과 Refresh Token 생성 (각각 만료 시간이 다름)
        String access = jwtUtil.createJwt("access", username, role, 600000L);   // 10분 유효
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);   // 1일 유효

        // 응답 헤더에 Access Token 추가
        response.setHeader("access", access);

        // 응답 쿠키에 Refresh Token 추가
        response.addCookie(createCookie("refresh", refresh));

        // 응답 상태를 200 (성공)으로 설정
        response.setStatus(HttpStatus.OK.value());
    }

    /**
     * 로그인 실패 시 호출되는 메서드입니다.
     * 인증에 실패한 경우 클라이언트에게 401 Unauthorized 응답을 반환합니다.
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        //로그인 실패시 401 응답 코드 반환
        response.setStatus(401);
    }

    /**
     * 쿠키 생성 메서드입니다.
     * JWT를 클라이언트의 브라우저에 쿠키로 전달할 때 사용됩니다. `HttpOnly` 속성을 통해 클라이언트에서 쿠키에 접근할 수 없도록 합니다.
     */
    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);

        // 쿠키의 유효 시간을 하루로 설정
        cookie.setMaxAge(24*60*60);

        //cookie.setSecure(true);
        //cookie.setPath("/");

        // HttpOnly 설정으로 클라이언트에서 쿠키 접근 불가 설정
        cookie.setHttpOnly(true);

        return cookie;
    }
}
