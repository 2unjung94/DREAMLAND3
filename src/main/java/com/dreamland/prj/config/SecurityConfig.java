package com.dreamland.prj.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.filter.CorsFilter;

import com.dreamland.prj.filter.CustomLogoutFilter;
import com.dreamland.prj.filter.JwtAuthenticationFilter;
import com.dreamland.prj.filter.JwtAuthorizationFilter;
import com.dreamland.prj.service.RefreshServiceImpl;
import com.dreamland.prj.utils.JWTUtil;

@Configuration 
@EnableWebSecurity 

public class SecurityConfig {
  
  private final CorsFilter corsFilter;
  private final AuthenticationConfiguration authenticationConfiguration;
  private final RefreshServiceImpl refreshService;
  private final JWTUtil jwtUtil;
  
  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
  
  
  public SecurityConfig(CorsFilter corsFilter, AuthenticationConfiguration authenticationConfiguration,
          JWTUtil jwtUtil, RefreshServiceImpl refreshService) {
    super();
    this.corsFilter = corsFilter;
    this.authenticationConfiguration = authenticationConfiguration;

    this.jwtUtil = jwtUtil;
    this.refreshService = refreshService;
  }


  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
    return configuration.getAuthenticationManager();
  }
  
  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    
    HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
    requestCache.setMatchingRequestParameterName(null);
    
    return http
        //.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class) // security 가 동작하기 전에 돌도록 filter 등록(최신 버전기준)
        .csrf(csrf ->csrf.disable())
        // jwt 세팅시 필요, 세션을 사용하지 않기 위해 사용
        .sessionManagement(t -> t.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) 
        .addFilter(corsFilter)  // @CrossOrigin(인증x), 시큐리티 필터에 등록 인증(o), jwt 세팅시 필요
        .httpBasic(httpBasic -> httpBasic.disable())
        .addFilterAt(new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshService), UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(new JwtAuthorizationFilter(jwtUtil), JwtAuthenticationFilter.class)    // 인가
        .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshService), LogoutFilter.class)
        .requestCache(request -> request
            .requestCache(requestCache))
        .formLogin(formLogin -> formLogin.disable())    // formlogin 사용 안함
        
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/login", "/loginPage", "/reissue").permitAll()
            .requestMatchers("/user/**", "/").hasAnyRole("ADMIN", "USER")
            .requestMatchers("/employee").hasRole("ADMIN")
            //.requestMatchers("/employee").permitAll()
            .anyRequest().permitAll()) 
        .build();
  }

  
}
