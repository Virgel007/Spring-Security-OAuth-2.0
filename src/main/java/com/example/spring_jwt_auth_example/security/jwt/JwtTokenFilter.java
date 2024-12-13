//package com.example.spring_jwt_auth_example.security.jwt;
//
//import com.example.spring_jwt_auth_example.security.UserDetailsServiceImpl;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.HttpHeaders;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@RequiredArgsConstructor
//@Slf4j
//@Component
//public class JwtTokenFilter extends OncePerRequestFilter {
//    // Проверяем Юзера из http строки и валидность токена потом ищем его уже
//
//    private final JwtUtils jwtUtils;
//
//    private final UserDetailsServiceImpl userDetailsService;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        try {
//            String jwtToken = getToken(request);
//
//            if (jwtToken != null && jwtUtils.validate(jwtToken)) {
//                String username = jwtUtils.getUsername(jwtToken);
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
//                        userDetails, null, userDetails.getAuthorities());
//
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//            }
//        } catch (Exception e) {
//            log.error("Cannot set user authentication: {}", e.getMessage());
//        }
//
//        filterChain.doFilter(request,response);
//    }
//
//    private String getToken(HttpServletRequest request) {
//        String headerAuth = request.getHeader(HttpHeaders.AUTHORIZATION);
//
//        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
//            return headerAuth.substring(7);
//        }
//
//        return null;
//    }
//}
