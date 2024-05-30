package com.dreamland.prj.config;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler  {

  public CustomSuccessHandler() {
    super();
    setUseReferer(true);
    setDefaultTargetUrl("/index");
  }

}
