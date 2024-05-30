package com.dreamland.prj.filter;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.dreamland.prj.dto.EmployeeDto;
import com.dreamland.prj.service.RefreshServiceImpl;
import com.dreamland.prj.utils.JWTUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 동작을 함

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
  
  private final AuthenticationManager authenticationManager;
  private final JWTUtil jwtUtil;
  //private final RefreshMapper refreshMapper;
  private final RefreshServiceImpl refreshService;
  
  public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshServiceImpl refreshService) {

    this.authenticationManager = authenticationManager;
    this.jwtUtil = jwtUtil;
    this.refreshService = refreshService;
  }
  
  // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException {
    
      String username = obtainUsername(request);
      String password = obtainPassword(request);
      
      // 인증 객체 생성
      UsernamePasswordAuthenticationToken authenticationToken =
          new UsernamePasswordAuthenticationToken(username, password, null);
      
      // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication 이 리턴됨
      // DB에 있는 username 과 password 가 일치한다
      Authentication authentication = authenticationManager.authenticate(authenticationToken);
      
      EmployeeDto principalDetails = (EmployeeDto) authentication.getPrincipal();
      // System.out.println("로그인 완료됨 " + principalDetails.getEmail());    // 로그인 정상적으로 되었다는 뜻
      
      // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨.
      // 리턴의 이유는 권한 관리를 security 가 대신 해주기 때문에 편하려고 하는거
      // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리때문에 session 넣어준다.
      
      return authenticationManager.authenticate(authenticationToken);
  }
  
  // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
  // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {

    // 유저정보
    String username = authResult.getName();
    
    Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
    Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
    GrantedAuthority auth = iterator.next();
    String role = auth.getAuthority();
    
    // 토큰생성
    String access = jwtUtil.createJwt("access", username, role, 600000L);
    String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);
    
    // refresh token db 저장
    addRefreshDto(username, refresh, 86400000L);
    
    // 응답 설정
    response.setHeader("access", access);
    response.addCookie(jwtUtil.createCookie("refresh", refresh));
    //response.sendRedirect("/user");
    response.setStatus(HttpStatus.OK.value());
    
  }
  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.getWriter().write("Authentication Failed: " + failed.getMessage());
  }
  
  private void addRefreshDto(String username, String refresh, Long expiredMs) {
    
    // 만료 일자 등록
    Date date = new Date(System.currentTimeMillis() + expiredMs);
    
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    String refDate = sdf.format(date);
    
    refreshService.addRefreshToken(username, refresh, refDate);

  }
 

}
