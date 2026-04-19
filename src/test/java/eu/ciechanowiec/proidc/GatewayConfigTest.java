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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

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

    // Inject a fake security context whenever the test header "X-Mock-Oidc-Token" is sent
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
        String tokenValue = "test-id-token";
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        webTestClient.get()
                .uri("/public/test")
                .header("X-Mock-Oidc-Token", tokenValue) // Instead of mutateWith()
                .exchange()
                .expectStatus()
                .isOk();

        // Used timeout so it fails immediately instead of hanging forever if routing breaks
        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();
        String relayedToken = recordedRequest.getHeaders().get(idTokenHeader);
        assertThat(relayedToken).isNull();
    }

    @Test
    void idTokenShouldBeRelayed() throws InterruptedException {
        String tokenValue = "test-id-token";
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", tokenValue)
                .exchange()
                .expectStatus()
                .isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();
        String relayedToken = recordedRequest.getHeaders().get(idTokenHeader);
        assertThat(relayedToken).isEqualTo(tokenValue);
    }

    @Test
    void externalIdTokenShouldBeRemoved() throws InterruptedException {
        mockWebServer.enqueue(new MockResponse().setBody("OK"));
        String externalToken = "some-token-from-outside";

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-internal-token")
                .header(idTokenHeader, externalToken)
                .exchange()
                .expectStatus()
                .isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();
        String relayedToken = recordedRequest.getHeaders().get(idTokenHeader);
        assertThat(relayedToken).isNotNull().isNotEqualTo(externalToken);
    }

    @Test
    void sessionCookieShouldBeRemovedAndOtherCookiesPreserved() throws InterruptedException {
        mockWebServer.enqueue(new MockResponse().setBody("OK"));
        String otherCookieName = "test-cookie";
        String otherCookieValue = "test-value";

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-token")
                .cookie(sessionCookieName, "some-session-value")
                .cookie(otherCookieName, otherCookieValue)
                .exchange()
                .expectStatus()
                .isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();
        String cookieHeader = recordedRequest.getHeaders().get("Cookie");
        assertThat(cookieHeader)
                .isNotNull()
                .contains(String.format("%s=%s", otherCookieName, otherCookieValue))
                .doesNotContain(sessionCookieName);
    }

    @Test
    void configuredHeadersShouldBeRemoved() throws InterruptedException {
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-token")
                .header("Authorization", "Bearer token")
                .header("X-XSRF-TOKEN", "csrf-token")
                .exchange()
                .expectStatus()
                .isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();
        for (String headerToRemove : headersToRemove) {
            assertThat(recordedRequest.getHeaders().get(headerToRemove)).isNull();
        }
    }

    @SuppressWarnings("MethodWithMultipleLoops")
    @Test
    void configuredHeadersAndCookiesShouldBeRemovedCaseInsensitively() throws InterruptedException {
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        // Sending headers and cookies with mixed/mangled casing
        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-token")
                .header("aUtHoRiZaTiOn", "Bearer token")
                .header("x-XsRf-ToKeN", "csrf-token")
                .cookie("XsRf-ToKeN", "csrf-token-cookie")
                .cookie("SLING.formauth", "form-auth-token")
                .exchange()
                .expectStatus()
                .isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();

        // 1. Verify headers were removed regardless of the case sent
        for (String headerToRemove : headersToRemove) {
            // MockWebServer gives access to headers case-insensitively,
            // so if it was relayed, it would be found here.
            assertThat(recordedRequest.getHeaders().get(headerToRemove)).isNull();
        }

        // 2. Verify cookies were removed regardless of the case sent
        Optional.ofNullable(recordedRequest.getHeaders().get("Cookie"))
                .ifPresent(
                        cookieHeader -> {
                            for (String cookieToRemove : cookiesToRemove) {
                                // Ensure the cookie string does not contain the target cookie
                                // using a case-insensitive match
                                assertThat(cookieHeader).doesNotContainIgnoringCase(cookieToRemove + "=");
                            }
                        }
                );
    }

    @Test
    void configuredCookiesShouldBeRemoved() throws InterruptedException {
        mockWebServer.enqueue(new MockResponse().setBody("OK"));

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-token")
                .cookie("XSRF-TOKEN", "csrf-token")
                .cookie("sling.formauth", "form-auth-token")
                .cookie("sling.sudo", "sudo-token")
                .exchange()
                .expectStatus()
                .isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest(5, TimeUnit.SECONDS);
        assertThat(recordedRequest).isNotNull();
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
        mockWebServer.enqueue(new MockResponse().setBody("OK"));
        int requestCountBefore = mockWebServer.getRequestCount();

        // No header sent, so the @TestConfiguration won't mock a login
        webTestClient.get()
                .uri("/api/test")
                .exchange()
                .expectStatus()
                .is3xxRedirection(); // Redirects to /login

        assertThat(mockWebServer.getRequestCount()).isEqualTo(requestCountBefore);
    }

    @SneakyThrows
    @Test
    void removeLocationHeader() {
        String loginPath = "/system/sling/form/login";
        mockWebServer.enqueue(
                new MockResponse()
                        .setBody("OK")
                        .addHeader("Location", loginPath)
        );

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-token")
                .exchange()
                .expectStatus().isFound()
                .expectHeader().location("/login");

        assertThat(mockWebServer.takeRequest(5, TimeUnit.SECONDS)).isNotNull();
    }

    @SneakyThrows
    @Test
    @SuppressWarnings({"TestMethodWithoutAssertion", "PMD.UnitTestShouldIncludeAssert"})
    void preserveLocationHeader() {
        String otherPath = "/some/other/path";
        mockWebServer.enqueue(
                new MockResponse()
                        .setBody("OK")
                        .addHeader("Location", otherPath)
        );

        webTestClient.get()
                .uri("/api/test")
                .header("X-Mock-Oidc-Token", "dummy-token")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Location", otherPath);

        mockWebServer.takeRequest(5, TimeUnit.SECONDS);
    }

    @SuppressWarnings("PackageVisibleInnerClass")
    @TestConfiguration
    static class MockSecurityConfig {
        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        public WebFilter mockOidcFilter() {
            return (exchange, chain) -> Optional.ofNullable(
                    exchange.getRequest().getHeaders().getFirst("X-Mock-Oidc-Token")
            ).map(
                    mockToken -> new OidcIdToken(
                            mockToken, Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user")
                    )
            ).map(
                    idToken -> new DefaultOidcUser(Collections.emptyList(), idToken)
            ).map(
                    oidcUser -> new OAuth2AuthenticationToken(oidcUser, Collections.emptyList(), "google")
            ).map(
                    auth -> {
                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .principal(Mono.just(auth))
                                .build();
                        return chain.filter(mutatedExchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                    }
            ).orElse(chain.filter(exchange));
        }
    }
}
