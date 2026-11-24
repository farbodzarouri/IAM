package com.authprovider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OpenApiDocumentationIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void unauthenticatedApiDocsRejectedWith401AndNonAdminForbidden() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/v3/api-docs").with(user("alice").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanFetchOpenApiV3SpecWithAllRestControllers() throws Exception {
        MvcResult result = mockMvc.perform(get("/v3/api-docs")
                        .with(user("admin").roles("ADMIN"))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode root = JSON.readTree(result.getResponse().getContentAsString());
        assertTrue(root.path("openapi").asText("").startsWith("3."),
                "Expected OpenAPI 3.x document, got: " + root.path("openapi"));

        JsonNode paths = root.path("paths");
        assertTrue(paths.isObject() && paths.size() > 0, "OpenAPI paths must be present");
        assertTrue(paths.has("/v1/api/auth/login"), "Missing /v1/api/auth/login");
        assertTrue(paths.has("/v1/api/users/all"), "Missing /v1/api/users/all");
        assertTrue(paths.has("/v1/api/persons"), "Missing /v1/api/persons");
        assertTrue(paths.has("/v1/api/registration"), "Missing /v1/api/registration");
        assertTrue(paths.has("/v1/api/oauth-clients"), "Missing /v1/api/oauth-clients");
        assertTrue(paths.has("/v1/api/radius-clients/all"), "Missing /v1/api/radius-clients/all");
        assertTrue(paths.has("/oauth2/token"), "Missing /oauth2/token");

        assertFalse(paths.has("/setup"), "Thymeleaf view /setup should not be in REST OpenAPI paths");
        assertFalse(paths.has("/users"), "Thymeleaf view /users should not be in REST OpenAPI paths");
        assertFalse(paths.has("/login"), "Thymeleaf view /login should not be in REST OpenAPI paths");

        JsonNode schemas = root.path("components").path("schemas");
        assertTrue(schemas.isObject() && schemas.size() > 0, "components.schemas must be non-empty");
        JsonNode bearerAuth = root.path("components").path("securitySchemes").path("bearerAuth");
        assertNotNull(bearerAuth);
        assertTrue("http".equalsIgnoreCase(bearerAuth.path("type").asText()),
                "Expected bearerAuth HTTP security scheme");
    }

    @Test
    void adminCanAccessSwaggerUi() throws Exception {
        MvcResult result = mockMvc.perform(get("/swagger-ui/index.html")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertTrue(body.toLowerCase().contains("swagger"), "Expected Swagger UI HTML page");
    }
}
