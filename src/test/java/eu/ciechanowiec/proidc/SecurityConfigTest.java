package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@TestPropertySource(
        properties = "proidc.paths_to_exclude.patterns=/public*/**"
)
class SecurityConfigTest {

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Autowired
    private WebTestClient webTestClient;

    @SuppressWarnings({"InstanceVariableMayNotBeInitialized", "MismatchedQueryAndUpdateOfCollection"})
    @Value("${proidc.paths_to_block.patterns}")
    private List<String> pathsToBlock;

    @SuppressWarnings({"InstanceVariableMayNotBeInitialized", "MismatchedQueryAndUpdateOfCollection"})
    @Value("${proidc.paths_to_exclude.patterns}")
    private List<String> pathsToExclude;

    @Test
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    void unauthenticatedRequestToSecuredEndpointRedirectsToLogin() {
        webTestClient.get()
                .uri("/any-path")
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().value("Location", location ->
                        assertThat(location).matches("/login")
                );
    }

    @Test
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    void requestToLogoutEndpointRedirectsToRoot() {
        webTestClient.get()
                .uri("/logout")
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().value("Location", location ->
                        assertThat(location).matches("/")
                );
    }

    @Test
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    void requestToBlockedPathRedirectsToRoot() {
        // Test with the first path pattern from the configuration
        // This assumes there's at least one path pattern configured
        String pathToTest = pathsToBlock.getFirst().replace("*", "").replace("/**", "");

        webTestClient.get()
                .uri(pathToTest)
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().value("Location", location ->
                        assertThat(location).matches("/")
                );
    }

    @SuppressWarnings({"TestMethodWithoutAssertion", "PMD.UnitTestShouldIncludeAssert"})
    @Test
    void loginPageIsAccessibleWithoutAuthentication() {
        webTestClient.get()
                .uri("/login")
                .exchange()
                .expectStatus().isOk();
    }

    @SuppressWarnings({"TestMethodWithoutAssertion", "PMD.UnitTestShouldIncludeAssert"})
    @Test
    @WithMockUser
    void postRequestToLogoutEndpointIsAllowed() {
        // Note: This test only verifies that POST to /logout is allowed
        // The actual logout functionality is tested in UpstreamServerLogoutSuccessHandlerTest

        // For POST requests to /logout, we need to include a CSRF token
        webTestClient.mutateWith(SecurityMockServerConfigurers.csrf())
                .post()
                .uri("/logout")
                .exchange()
                .expectStatus().is3xxRedirection();
    }

    @SuppressWarnings({"TestMethodWithoutAssertion", "PMD.UnitTestShouldIncludeAssert"})
    @Test
    void excludedPathsAreAccessibleWithoutAuthentication() {
        // This test verifies that paths configured to be excluded from authentication
        // are accessible without authentication

        String pathToTest = "/public/resource";

        webTestClient.get()
                .uri(pathToTest)
                .exchange()
                .expectStatus().isOk();
    }

    @SuppressWarnings({"PackageVisibleInnerClass", "unused", "EmptyClass"})
    @TestConfiguration
    static class WebTestConfig {
        @RestController
        static class DummyController {
            @GetMapping("/public/resource")
            public Mono<String> dummyEndpoint() {
                return Mono.just("OK");
            }
        }
    }
}
