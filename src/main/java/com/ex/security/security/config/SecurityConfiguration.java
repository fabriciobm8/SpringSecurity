package com.ex.security.security.config;

import com.ex.security.security.authentication.UserAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

  @Autowired
  private UserAuthenticationFilter userAuthenticationFilter;

  public static final String [] ENDPOINST_WITH_AUTHENTICATION_NOT_REQUIRED = {
      "/users/login", //url que usaremos para fazer login.
      "/users" // url que usaremos para criar um usuário.
  };

  //Endpoints



}
