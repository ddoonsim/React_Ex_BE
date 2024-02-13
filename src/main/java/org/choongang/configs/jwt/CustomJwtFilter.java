package org.choongang.configs.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

/**
 * 요청 전 필터링
 */
@Component
@RequiredArgsConstructor
public class CustomJwtFilter extends GenericFilterBean {

    private final TokenProvider tokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)request;

        /* 요청 헤더 Authoriztion 항목의 JWT 토큰 추출 S */
        String header = req.getHeader("Authorization");
        String jwt = null;
        if (StringUtils.hasText(header)) {
            // Bearer "토큰" --> 토큰 추출(문자열의 7번째 인덱스부터 추출)
            jwt = header.substring(7);
        }
        /* 요청 헤더 Authoriztion 항목의 JWT 토큰 추출 E */

        /* 로그인 유지 처리 S */
        if (StringUtils.hasText(jwt)) {
            tokenProvider.validateToken(jwt); // 토큰 비정상 시 --> 예외 발생

            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        /* 로그인 유지 처리 E */

        chain.doFilter(request, response);
    }
}
