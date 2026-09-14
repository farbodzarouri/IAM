package com.authprovider.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                        (requests) -> requests.requestMatchers("/", "/login", "/v1/api/**", "/users/**").permitAll().anyRequest()
                                .authenticated())
                .formLogin((form) -> form.loginPage("/login").permitAll()).logout((logout) -> logout.permitAll())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
