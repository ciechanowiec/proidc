package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@SuppressWarnings("TypeName")
class UpstreamServerLogoutSuccessHandlerTest {

    private static final String UPSTREAM_LOGOUT_URL = "http://upstream/logout";
    private static final String ID_TOKEN_HEADER_NAME = "X-ID-Token";

    @Mock
    private ServerLogoutSuccessHandler delegateHandler;
    private WebClient.RequestBodyUriSpec requestBodyUriSpec;
    private UpstreamServerLogoutSuccessHandler logoutSuccessHandler;

    @SuppressWarnings("resource")
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);

        // Create a WebClient mock with more detailed verification capabilities
        WebClient webClient = mock(WebClient.class);
        requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(any(String.class))).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.header(any(String.class), any())).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(Mono.empty());

        // Set up a delegate handler
        when(delegateHandler.onLogoutSuccess(any(), any())).thenReturn(Mono.empty());

        // Create the handler under test
        logoutSuccessHandler = new UpstreamServerLogoutSuccessHandler(
                webClient,
                UPSTREAM_LOGOUT_URL,
                ID_TOKEN_HEADER_NAME,
                delegateHandler
        );
    }

    @Test
    void shouldDelegateForNonOidcAuthentication() {
        // Given
        Authentication authentication = mock(Authentication.class);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/logout").build());
        WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, mock(WebFilterChain.class));

        // When
        logoutSuccessHandler.onLogoutSuccess(webFilterExchange, authentication).block();

        // Then
        verify(delegateHandler).onLogoutSuccess(webFilterExchange, authentication);
        // Verify that the WebClient was not called
        verify(requestBodyUriSpec, never()).header(eq(ID_TOKEN_HEADER_NAME), any());
    }

    @SuppressWarnings("MagicNumber")
    @Test
    void shouldCallUpstreamWithIdTokenAndThenDelegate() {
        // Given
        String tokenValue = "test-id-token";
        OidcIdToken idToken = new OidcIdToken(
                tokenValue, Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user")
        );
        OAuth2User oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
        OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
        when(authentication.getPrincipal()).thenReturn(oidcUser);

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/logout").build());
        WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, mock(WebFilterChain.class));

        // When
        logoutSuccessHandler.onLogoutSuccess(webFilterExchange, authentication).block();

        // Then
        // Verify that the WebClient was called with the correct URL
        verify(requestBodyUriSpec).uri(UPSTREAM_LOGOUT_URL);

        // Verify that the WebClient was called with the correct ID token header
        verify(requestBodyUriSpec).header(eq(ID_TOKEN_HEADER_NAME), eq(tokenValue));

        // Verify that the delegate handler was called
        verify(delegateHandler).onLogoutSuccess(webFilterExchange, authentication);
    }

    @SuppressWarnings("MagicNumber")
    @Test
    void shouldContinueWithDelegateEvenIfUpstreamCallFails() {
        // Given
        String tokenValue = "test-id-token";
        OidcIdToken idToken = new OidcIdToken(
                tokenValue, Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user")
        );
        OAuth2User oidcUser = new DefaultOidcUser(Collections.emptyList(), idToken);
        OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
        when(authentication.getPrincipal()).thenReturn(oidcUser);

        // Set up WebClient to throw an exception
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        when(requestBodyUriSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(Mono.error(new RuntimeException("Upstream call failed")));

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/logout").build());
        WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, mock(WebFilterChain.class));

        // When
        logoutSuccessHandler.onLogoutSuccess(webFilterExchange, authentication).block();

        // Then
        // Verify that the delegate handler was still called despite the upstream call failing
        verify(delegateHandler).onLogoutSuccess(webFilterExchange, authentication);
    }
}
