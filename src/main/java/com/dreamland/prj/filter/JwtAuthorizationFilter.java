package com.dreamland.prj.filter;

import java.io.IOException;
import java.io.PrintWriter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.dreamland.prj.dto.EmployeeDto;
import com.dreamland.prj.utils.JWTUtil;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// 시큐리티가 여러가지 filter 를 가지고 있는데, 그 필터 중 BasicAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약 권한이나 인증이 필요한 주소가 아리나면 이 필터를 타지 않음

public class JwtAuthorizationFilter extends OncePerRequestFilter{

  private JWTUtil jwtUtil;
  
  public JwtAuthorizationFilter(JWTUtil jwtUtil) {
    super();
    this.jwtUtil = jwtUtil;
  }


  // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    
    // access token 가져오기
    String accessToken = request.getHeader("access");
    
    // 토큰이 없다면 다음 필터로 넘김
    if(accessToken == null) {
      chain.doFilter(request, response);
      return;
    }
    
    // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
    try {
      
      jwtUtil.isExpired(accessToken);
      
    } catch (ExpiredJwtException e) {
      
      // responseBody
      PrintWriter writer = response.getWriter();
      writer.print("access token expired");
      
      // response status code
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }
    
    // token 이 access 인지 확인 (발급시 페이로드에 명시)
    String category = jwtUtil.getCategory(accessToken);
    
    if(!category.equals("access")) {
      
      // responseBody
      PrintWriter writer = response.getWriter();
      writer.print("invaild access token");
      
      // response status code
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }
    
    // username, role 값 획득
    String username = jwtUtil.getUsername(accessToken);
    String role = jwtUtil.getRole(accessToken);

    EmployeeDto user = EmployeeDto.builder()
                      .email(username)
                      .role(role)
                    .build();
    
    Authentication authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    
    // 세션 등록
    SecurityContextHolder.getContext().setAuthentication(authToken);
    
    chain.doFilter(request, response);
    
  }
  
}
