package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.util.Map;

@SuppressWarnings("TestMethodWithoutAssertion")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class CsrfControllerTest {

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Autowired
    private WebTestClient webTestClient;

    @Test
    @WithMockUser
    @SuppressWarnings({"PMD.UnitTestShouldIncludeAssert", "MagicNumber"})
    void shouldReturnCsrfToken() {
        webTestClient.get()
                .uri("/csrf")
                .exchange()
                .expectStatus().isOk()
                .expectCookie().exists("XSRF-TOKEN")
                .expectCookie().maxAge("XSRF-TOKEN", Duration.ofSeconds(3600))
                .expectBody()
                .jsonPath("$.token").exists()
                .jsonPath("$.headerName").exists()
                .jsonPath("$.parameterName").exists();
    }

    @Test
    @WithMockUser
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    void shouldRejectPostRequestWithoutCsrfToken() {
        webTestClient.post()
                .uri("/api/test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("test", "value"))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    @WithMockUser
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    void shouldAllowPostRequestWithValidCsrfToken() {
        // For this test, we'll use a different approach
        // Instead of trying to test a non-existent endpoint, we'll test the /logout endpoint
        // which is a real endpoint that requires CSRF protection
        webTestClient.mutateWith(SecurityMockServerConfigurers.csrf())
                .post()
                .uri("/logout")
                .exchange()
                .expectStatus().is3xxRedirection(); // Should redirect after successful logout
    }
}
