package com.authprovider.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                        .requestMatchers(
                                "/login",
                                "/mfa",
                                "/error",
                                "/v1/api/auth/**",
                                "/v1/api/mfa/**",
                                "/v1/api/otp/validate",
                                "/v1/api/otp/validate-ocra"
                        ).permitAll()
                        .requestMatchers(
                                "/users/**",
                                "/v1/api/users/**",
                                "/v1/api/otp/generate/**"
                        ).authenticated()
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .formLogin((form) -> form.loginPage("/login").permitAll())
                .logout((logout) -> logout.permitAll())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
