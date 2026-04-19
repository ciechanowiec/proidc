package eu.ciechanowiec.proidc;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureWebTestClient
@TestPropertySource(
        properties = "proidc.paths_to_exclude.patterns=/public*/**"
)
@SuppressWarnings({"MultipleStringLiterals", "PMD.AvoidDuplicateLiterals"})
class SecurityConfigTest {

    @Autowired
    private WebTestClient webTestClient;

    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    @Value("${proidc.paths_to_block.patterns}")
    private List<String> pathsToBlock;

    @SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "unused"})
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

    @SuppressWarnings("PackageVisibleInnerClass")
    @Nested
    @SpringBootTest
    @AutoConfigureWebTestClient
    @TestPropertySource(
            properties = {
                    "proidc.strings_in_paths_to_block=INSTALL,Config,j_security_check",
                    "proidc.paths_to_exclude.patterns=/public*/**"
            }
    )
    class StringsInPathsToBlockTest {

        @Autowired
        private WebTestClient stringsTestClient;

        @ParameterizedTest
        @ValueSource(
                strings = {
                        "/install", "/INSTALL", "/some/install/path", "/some/INSTALL/path",
                        "/config", "/CONFIG", "/some/config/path", "/some/CONFIG/path",
                        "/j_security_check", "/J_SECURITY_CHECK", "/some/j_security_check/path",
                        "/path/with/install/inside", "/path/with/config/inside", "/path/with/j_security_check/inside",
                        "/path/author.install/me", "/path/author.config/me", "/path/author.j_security_check/me",
                        "/path/install.author", "/path/iiinstallll/m"
                }
        )
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldBlockPathsContainingBlockedStrings(String path) {
            stringsTestClient.get()
                    .uri(path)
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/")
                    );
        }

        @Test
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldNotBlockPathsNotContainingBlockedStrings() {
            // This path doesn't contain "install" or "config"
            // It's not in the excluded list, so it should redirect to /login (standard behavior)
            stringsTestClient.get()
                    .uri("/allowed-path")
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/login")
                    );
        }

        @Test
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldBlockAuthorizedRequestToBlockedStringPath() {
            // Authorized request should still be blocked if it contains a blocked string
            stringsTestClient.mutateWith(SecurityMockServerConfigurers.mockUser())
                    .get()
                    .uri("/some/install/path")
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/")
                    );
        }

        @Test
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldNotBlockWhenBlockedStringIsInQueryParameter() {
            // Blocked string in a query parameter should NOT cause blocking
            stringsTestClient.get()
                    .uri("/allowed-path?param=install")
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/login")
                    );
        }

        @Test
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldBlockPathWithMultipleBlockedStrings() {
            stringsTestClient.get()
                    .uri("/path/containing/INSTALL/and/Config")
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/")
                    );
        }

        @Test
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldBlockEvenIfPathIsExcludedInOtherFilter() {
            // /public/resource is in patternsOfPathsToExclude (see @TestPropertySource),
            // but if it contains a blocked string, it should still be blocked
            // by restrictedPathsDenyFilterChain (Order(1))
            stringsTestClient.get()
                    .uri("/public/install/resource")
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/")
                    );
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "/path/with/in-stall", // hyphenated
                "/path/with/inst.all", // dotted
                "/path/with/inst_all", // underscored
                "/confi",              // prefix
                "/onfig"               // suffix
        })
        @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
        void shouldNotBlockPathsWithNearMatches(String path) {
            stringsTestClient.get()
                    .uri(path)
                    .exchange()
                    .expectStatus().is3xxRedirection()
                    .expectHeader().value("Location", location ->
                            assertThat(location).isEqualTo("/login")
                    );
        }
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

    @SuppressWarnings("PackageVisibleInnerClass")
    @Nested
    class CreateCsrfMatcherTest {

        private SecurityConfig securityConfig;

        @BeforeEach
        void setup() {
            securityConfig = new SecurityConfig(
                    "http://localhost:8080/logout",
                    "X-ID-Token",
                    ".*",
                    Collections.emptyList(),
                    Collections.emptyList(),
                    List.of("/public/**")
            );
        }

        @SneakyThrows
        @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
        private ServerWebExchangeMatcher getCsrfMatcher() {
            Method method = SecurityConfig.class.getDeclaredMethod("createCsrfMatcher");
            method.setAccessible(true);
            return (ServerWebExchangeMatcher) method.invoke(securityConfig);
        }

        @Test
        void shouldNotMatchOnExcludedPathWithPost() {
            ServerWebExchangeMatcher csrfMatcher = getCsrfMatcher();
            MockServerHttpRequest request = MockServerHttpRequest.post("/public/some/resource").build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            ServerWebExchangeMatcher.MatchResult result = csrfMatcher.matches(exchange).block();

            assertThat(result).isNotNull();
            assertThat(result.isMatch()).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "TRACE"})
        void shouldNotMatchOnNonExcludedPathWithSafeMethods(String methodName) {
            ServerWebExchangeMatcher csrfMatcher = getCsrfMatcher();
            MockServerHttpRequest request = MockServerHttpRequest.method(
                    HttpMethod.valueOf(methodName), "/protected/resource"
            ).build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            ServerWebExchangeMatcher.MatchResult result = csrfMatcher.matches(exchange).block();

            assertThat(result).isNotNull();
            assertThat(result.isMatch()).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {"POST", "PUT", "DELETE", "PATCH"})
        void shouldMatchOnNonExcludedPathWithStateChangingMethods(String methodName) {
            ServerWebExchangeMatcher csrfMatcher = getCsrfMatcher();
            MockServerHttpRequest request = MockServerHttpRequest.method(
                    HttpMethod.valueOf(methodName), "/protected/resource"
            ).build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            ServerWebExchangeMatcher.MatchResult result = csrfMatcher.matches(exchange).block();

            assertThat(result).isNotNull();
            assertThat(result.isMatch()).isTrue();
        }
    }
}
