package com.example.demo.JwtSetting;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {

    log.info("Request URI: {}", request.getRequestURI());

    if (!request.getRequestURI().contains("auth/login") && !request.getRequestURI().contains("favicon")) {
      log.info("Checking token...");

      try {
        String jwt = getJwtFromRequest(request);

        if (StringUtils.isNotEmpty(jwt) && JwtTokenProvider.validateToken(jwt)) {
          String userId = JwtTokenProvider.getUserIdFromJWT(jwt);
          log.info("Authenticated user ID: {}", userId);

          UserAuthentication authentication = new UserAuthentication(userId, null, null);
          authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

          SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
          log.warn("JWT is missing or invalid");
          // Send 401 Unauthorized response
          response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
          return; // End the filter chain
        }
      } catch (Exception ex) {
        log.error("Could not set user authentication in security context", ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error");
        return; // End the filter chain
      }
    }

    filterChain.doFilter(request, response);
  }

  private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    log.info("Authorization header: {}", bearerToken);

    if (StringUtils.isNotEmpty(bearerToken) && bearerToken.startsWith("Bearer ")) {
      log.info("Bearer token detected");
      return bearerToken.substring("Bearer ".length());
    }

    return null;
  }
}
