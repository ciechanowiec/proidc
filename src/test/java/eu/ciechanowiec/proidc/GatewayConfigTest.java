package eu.ciechanowiec.proidc;

import lombok.SneakyThrows;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOidcLogin;

@SuppressWarnings({"unused", "MultipleStringLiterals", "PMD.AvoidDuplicateLiterals", "MagicNumber"})
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.cloud.gateway.server.webflux.routes[0].id=test-service",
                "spring.cloud.gateway.server.webflux.routes[0].uri=http://localhost:${test.server.port}",
                "spring.cloud.gateway.server.webflux.routes[0].predicates[0]=Path=/**",
                "proidc.paths_to_exclude.patterns=/public*/**"
        }
)
@AutoConfigureWebTestClient
class GatewayConfigTest {

    @SuppressWarnings({"StaticVariableMayNotBeInitialized", "FieldNamingConvention"})
    private static MockWebServer mockWebServer;

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Autowired
    private WebTestClient webTestClient;

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Value("${proidc.id_token.header_name}")
    private String idTokenHeader;

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Value("${server.reactive.session.cookie.name:SESSION}")
    private String sessionCookieName;

    @SuppressWarnings({"InstanceVariableMayNotBeInitialized", "MismatchedReadAndWriteOfArray"})
    @Value("${proidc.headers_to_remove}")
    private String[] headersToRemove;

    @SuppressWarnings({"InstanceVariableMayNotBeInitialized", "MismatchedReadAndWriteOfArray"})
    @Value("${proidc.cookies_to_remove}")
    private String[] cookiesToRemove;

    @BeforeAll
    static void setup() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
    }

    @SuppressWarnings("StaticVariableUsedBeforeInitialization")
    @AfterAll
    static void teardown() throws IOException {
        mockWebServer.shutdown();
    }

    @SuppressWarnings({"unused", "StaticVariableUsedBeforeInitialization"})
    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("test.server.port", mockWebServer::getPort);
    }

    @Test
    void idTokenShouldNotBeRelayedForExcludedPaths() throws InterruptedException {
        // Given
        String tokenValue = "test-id-token";
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        OidcIdToken idToken = new OidcIdToken(
                tokenValue, Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user")
        );
        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

        // When
        webTestClient.mutateWith(mockOidcLogin().oidcUser(oidcUser))
                .get()
                .uri("/public/test")
                .exchange()
                .expectStatus()
                .isOk();

        // Then
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        String relayedToken = recordedRequest.getHeaders().get(idTokenHeader);
        assertThat(relayedToken).isNull();
    }

    @SuppressWarnings("MagicNumber")
    @Test
    void idTokenShouldBeRelayed() throws InterruptedException {
        // Given
        String tokenValue = "test-id-token";
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        OidcIdToken idToken = new OidcIdToken(
                tokenValue, Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user")
        );
        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);

        // When
        webTestClient.mutateWith(mockOidcLogin().oidcUser(oidcUser))
                .get()
                .uri("/api/test")
                .exchange()
                .expectStatus()
                .isOk();

        // Then
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        String relayedToken = recordedRequest.getHeaders().get(idTokenHeader);
        assertThat(relayedToken).isEqualTo(tokenValue);
    }

    @Test
    void externalIdTokenShouldBeRemoved() throws InterruptedException {
        // Given
        mockWebServer.enqueue(new MockResponse().setBody("OK"));
        String externalToken = "some-token-from-outside";

        // When
        webTestClient.mutateWith(mockOidcLogin())
                .get()
                .uri("/api/test")
                .header(idTokenHeader, externalToken)
                .exchange()
                .expectStatus()
                .isOk();

        // Then
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        String relayedToken = recordedRequest.getHeaders().get(idTokenHeader);
        assertThat(relayedToken).isNotNull()
                .isNotEqualTo(externalToken);
    }

    @Test
    void sessionCookieShouldBeRemovedAndOtherCookiesPreserved() throws InterruptedException {
        // Given
        mockWebServer.enqueue(new MockResponse().setBody("OK"));
        String otherCookieName = "test-cookie";
        String otherCookieValue = "test-value";

        // When
        webTestClient.mutateWith(mockOidcLogin())
                .get()
                .uri("/api/test")
                .cookie(sessionCookieName, "some-session-value")
                .cookie(otherCookieName, otherCookieValue)
                .exchange()
                .expectStatus()
                .isOk();

        // Then
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        String cookieHeader = recordedRequest.getHeaders().get("Cookie");
        assertThat(cookieHeader)
                .isNotNull()
                .contains(String.format("%s=%s", otherCookieName, otherCookieValue))
                .doesNotContain(sessionCookieName);
    }

    @Test
    void configuredHeadersShouldBeRemoved() throws InterruptedException {
        // Given
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        // When
        webTestClient.mutateWith(mockOidcLogin())
                .get()
                .uri("/api/test")
                .header("Authorization", "Bearer token")
                .header("X-XSRF-TOKEN", "csrf-token")
                .exchange()
                .expectStatus()
                .isOk();

        // Then
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        for (String headerToRemove : headersToRemove) {
            assertThat(recordedRequest.getHeaders().get(headerToRemove)).isNull();
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
    void configuredCookiesShouldBeRemoved() throws InterruptedException {
        // Given
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        // When
        webTestClient.mutateWith(mockOidcLogin())
                .get()
                .uri("/api/test")
                .cookie("XSRF-TOKEN", "csrf-token")
                .cookie("sling.formauth", "form-auth-token")
                .cookie("sling.sudo", "sudo-token")
                .exchange()
                .expectStatus()
                .isOk();

        // Then
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        Optional.ofNullable(recordedRequest.getHeaders().get("Cookie"))
                .ifPresent(
                        cookieHeader -> {
                            for (String cookieToRemove : cookiesToRemove) {
                                assertThat(cookieHeader).doesNotContain(cookieToRemove + "=");
                            }
                        }
                );
    }

    @Test
    void unauthenticatedRequestShouldNotHaveIdTokenHeader() {
        // Given
        mockWebServer.enqueue(new MockResponse().setBody("OK"));
        int requestCountBefore = mockWebServer.getRequestCount();
        // When - Note: No mockOidcLogin() here
        webTestClient.get()
                .uri("/api/test")
                .exchange()
                .expectStatus()
                .is3xxRedirection(); // Redirects to /login
        // Then
        // Verify that the request did not reach the upstream server
        assertThat(mockWebServer.getRequestCount()).isEqualTo(requestCountBefore);
    }

    @SneakyThrows
    @Test
    void removeLocationHeader() {
        // Given
        String loginPath = "/system/sling/form/login";
        mockWebServer.enqueue(
                new MockResponse()
                        .setBody("OK")
                        .addHeader("Location", loginPath)
        );

        // When
        webTestClient.mutateWith(mockOidcLogin())
                .get()
                .uri("/api/test")
                .exchange()
                .expectStatus().isFound()
                .expectHeader().location("/login");

        // Then
        // Verify that a request was made to the upstream server
        assertThat(mockWebServer.takeRequest()).isNotNull();
    }

    @SneakyThrows
    @Test
    @SuppressWarnings({"TestMethodWithoutAssertion", "PMD.UnitTestShouldIncludeAssert"})
    void preserveLocationHeader() {
        // Given
        String otherPath = "/some/other/path";
        mockWebServer.enqueue(
                new MockResponse()
                        .setBody("OK")
                        .addHeader("Location", otherPath)
        );

        // When
        webTestClient.mutateWith(mockOidcLogin())
                .get()
                .uri("/api/test")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Location", otherPath);

        // Then
        mockWebServer.takeRequest();
    }
}
