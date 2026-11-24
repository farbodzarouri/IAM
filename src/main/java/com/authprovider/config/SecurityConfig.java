package com.authprovider.config;

import com.authprovider.oauth2.AccessTokenService;
import com.authprovider.oauth2.BearerTokenAuthenticationFilter;
import com.authprovider.service.AuthAuditService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * OAuth 2.0 authorization server endpoints. Client authentication (HTTP Basic) and RFC 6749 error
     * responses are handled by the endpoints themselves; the chain is stateless and CSRF-exempt.
     */
    @Bean
    @Order(0)
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/oauth2/**")
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/oauth2/token", "/oauth2/introspect", "/oauth2/revoke", "/oauth2/jwks")
                        .permitAll()
                        .anyRequest().denyAll())
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .securityContext((context) -> context.requireExplicitSave(true))
                .exceptionHandling((ex) -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.NOT_FOUND)))
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http, AccessTokenService accessTokenService,
                                                      AuthAuditService auditService) throws Exception {
        http.securityMatcher("/v1/api/**")
                .addFilterBefore(new BearerTokenAuthenticationFilter(accessTokenService, auditService),
                        AnonymousAuthenticationFilter.class)
                .authorizeHttpRequests((requests) -> requests
                        // Connected systems: scoped RFC 6750 bearer access tokens.
                        .requestMatchers("/v1/api/auth/login").hasAuthority("SCOPE_auth:login")
                        .requestMatchers("/v1/api/otp/validate", "/v1/api/otp/validate-ocra")
                        .hasAuthority("SCOPE_otp:validate")
                        .requestMatchers("/v1/api/mfa/preauth").hasAuthority("SCOPE_mfa:preauth")
                        // Client registries (OAuth 2.0 and the cross-type client listing): administrators only.
                        .requestMatchers("/v1/api/oauth-clients", "/v1/api/oauth-clients/**").hasRole("ADMIN")
                        .requestMatchers("/v1/api/clients", "/v1/api/clients/**").hasRole("ADMIN")
                        // User registration & client assignments: administrators only.
                        .requestMatchers("/v1/api/registration", "/v1/api/registration/**",
                                "/v1/api/users/register",
                                "/v1/api/users/*/radius-clients", "/v1/api/users/*/radius-clients/**",
                                "/v1/api/users/*/oauth-clients", "/v1/api/users/*/oauth-clients/**")
                        .hasRole("ADMIN")
                        .requestMatchers(
                                "/v1/api/admin/auth/**",
                                "/v1/api/setup/**"
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
                        .requestMatchers(
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/swagger-ui.html",
                                "/swagger-ui/**"
                        ).hasRole("ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling((ex) -> ex
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new AntPathRequestMatcher("/v3/api-docs"))
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new AntPathRequestMatcher("/v3/api-docs/**"))
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                AnyRequestMatcher.INSTANCE))
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
