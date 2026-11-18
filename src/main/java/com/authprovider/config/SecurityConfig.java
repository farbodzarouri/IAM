package com.authprovider.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/v1/api/**")
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers(
                                "/v1/api/auth/**",
                                "/v1/api/admin/auth/**",
                                "/v1/api/setup/**",
                                "/v1/api/mfa/**",
                                "/v1/api/otp/validate",
                                "/v1/api/otp/validate-ocra"
                        ).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling((ex) -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                        .requestMatchers(
                                "/setup",
                                "/setup/**",
                                "/login",
                                "/login/otp",
                                "/login/enroll",
                                "/mfa",
                                "/error"
                        ).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling((ex) -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .csrf((csrf) -> csrf.ignoringRequestMatchers("/mfa"))
                .logout((logout) -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll());

        return http.build();
    }
}
