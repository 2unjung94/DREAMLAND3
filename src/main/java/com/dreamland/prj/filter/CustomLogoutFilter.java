package com.dreamland.prj.filter;

import java.io.IOException;

import org.springframework.web.filter.GenericFilterBean;

import com.dreamland.prj.service.RefreshServiceImpl;
import com.dreamland.prj.utils.JWTUtil;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomLogoutFilter extends GenericFilterBean {
  private final JWTUtil jwtUtil;
  private final RefreshServiceImpl refreshService;

  public CustomLogoutFilter(JWTUtil jwtUtil, RefreshServiceImpl refreshService) {
    this.jwtUtil = jwtUtil;
    this.refreshService = refreshService;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    
  }
  
  private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
      throws IOException, ServletException {
    
    // 경로와 메소드 확인
    String requestUri = request.getRequestURI();
    if(!requestUri.matches("^\\/logout$")) {
      filterChain.doFilter(request, response);
      return;
    }
    String requestMethod = request.getMethod();
    if(!requestMethod.equals("POST")) {
      filterChain.doFilter(request, response);
      return;
    }
    
    // refresh token 가져오기
    String refresh = null;
    Cookie[] cookies = request.getCookies();
    for(Cookie cookie : cookies) {
      if(cookie.getName().equals("refresh")) {
        refresh = cookie.getValue();
      }
    }
    
    // refresh token null check
    if (refresh == null) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    
    // 유효기간 체크
    try {
      jwtUtil.isExpired(refresh);
    } catch (ExpiredJwtException e) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    
    // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
    String category = jwtUtil.getCategory(refresh);
    if(!category.equals("refresh")) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    
    // DB에 저장되어 있는지 확인
    Boolean isExist = refreshService.searchRefreshToken(refresh) > 0;
    if (!isExist) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    
    // 로그아웃 진행
    // refresh token db에서 제거
    refreshService.deleteByRefresh(refresh);
    
    // refresh 토큰 cookie 값 0 설정
    Cookie cookie = new Cookie("refresh", null);
    cookie.setMaxAge(0);
    cookie.setPath("/");
    
    response.addCookie(cookie);
    response.setStatus(HttpServletResponse.SC_OK);    
  }
}
