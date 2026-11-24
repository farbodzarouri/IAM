package com.authprovider.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Global OpenAPI v3 configuration exposed at {@code /v3/api-docs} and Swagger UI.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI iamOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("IAM Service API")
                        .version("1.0")
                        .description("Identity, MFA, OAuth 2.0, and RADIUS management and authentication APIs"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }
}
