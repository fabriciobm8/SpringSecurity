package com.ex.security.security.authentication;

import com.ex.security.entities.User;
import com.ex.security.repositories.UserRepository;
import com.ex.security.security.config.SecurityConfiguration;
import com.ex.security.security.userdetails.UserDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.Authenticator;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class UserAuthenticationFilter extends OncePerRequestFilter {

  @Autowired
  private JwtTokenService jwtTokenService; //Service que definimos anteriormente

  @Autowired
  private UserRepository userRepository; //Repository que definimos anteriormente

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    // Verifica se o endpoint requer autenticação antes de processar a requisição
    if (checkIfEndpointIsNotPublic(request)) {
      String token = recoveryToken(request); //Recupera o token do cabeçalho authorization da requisição.
      if (token != null) {
        String subject = jwtTokenService.getSubjectFromToken(
            token);//Obtem o assunto(neste caso, o nome do usuário) do token.
        User user = userRepository.findByEmail(subject)
            .get();//Busca o usuario pelo email (que é o assunto do token).
        UserDetailsImpl userDetails = new UserDetailsImpl(
            user);//Cria um UserDetails com o usuario encontrado.

        //Cria um objeto de autenticação do Spring Security
        Authentication authentication =
            new UsernamePasswordAuthenticationToken(userDetails.getUsername(), null,
                userDetails.getAuthorities());

        //Define o objeto de autenticação no contexto de segurança do Spring Security
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } else {
        throw new RuntimeException("O token está ausente.");
      }
    }
    filterChain.doFilter(request,response);//Continua o processamento da requisição
  }

  //Recupera o token do cabeçalho autorization da requisição.
  private String recoveryToken(HttpServletRequest request) {
    String autorizationHeader = request.getHeader("Authorization");
    if(autorizationHeader != null) {
      return autorizationHeader.replace("Bearer ","");
    }
    return null;
  }

  //Verifica se o endpoint requer autenticação antes de processar a requisição
  private boolean checkIfEndpointIsNotPublic(HttpServletRequest request) {
    String requestURI = request.getRequestURI();
    return !Arrays.asList(SecurityConfiguration.ENDPOINST_WITH_AUTHENTICATION_NOT_REQUIRED).contains(requestURI);
  }

}
