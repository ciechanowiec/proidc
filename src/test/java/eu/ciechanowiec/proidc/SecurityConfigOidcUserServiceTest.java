package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings({"MagicNumber", "TypeName"})
class SecurityConfigOidcUserServiceTest {

    private ClientRegistration basicClientRegistration() {
        return ClientRegistration.withRegistrationId("test")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // minimal values to satisfy builder; do not set userInfoUri to avoid network calls
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://auth.example")
                .tokenUri("http://token.example")
                .scope("openid", "profile", "email")
                .build();
    }

    @Test
    void oidcUserServiceAllowsMatchingHdClaim() {
        SecurityConfig config = new SecurityConfig(
                "http://upstream/logout",
                "X-ID-Token",
                "example\\.com", // regex for allowed hd
                List.of(), // no blocked paths needed for this test
                List.of()
        );

        ReactiveOAuth2UserService<OidcUserRequest, OidcUser> service = config.oidcUserService();

        ClientRegistration clientRegistration = basicClientRegistration();

        Map<String, Object> claims = Map.of("hd", "example.com", "sub", "user123", "email", "u@example.com");
        OidcIdToken idToken = new OidcIdToken("id-token-value", Instant.now(), Instant.now().plusSeconds(60), claims);

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "access", Instant.now(), Instant.now().plusSeconds(60)
        );

        OidcUserRequest request = new OidcUserRequest(clientRegistration, accessToken, idToken);

        OidcUser result = service.loadUser(request).block();

        assertNotNull(result, "OidcUser should be returned for matching hd claim");
        assertEquals("example.com", result.getClaimAsString("hd"));
    }

    @Test
    void oidcUserServiceRejectsNonMatchingHdClaim() {
        SecurityConfig config = new SecurityConfig(
                "http://upstream/logout",
                "X-ID-Token",
                "example\\.com", // only example.com allowed
                Collections.emptyList(),
                Collections.emptyList()
        );

        ReactiveOAuth2UserService<OidcUserRequest, OidcUser> service = config.oidcUserService();

        ClientRegistration clientRegistration = basicClientRegistration();

        Map<String, Object> claims = Map.of("hd", "other.com", "sub", "user123");
        OidcIdToken idToken = new OidcIdToken("id-token-value", Instant.now(), Instant.now().plusSeconds(60), claims);

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "access", Instant.now(), Instant.now().plusSeconds(60)
        );

        OidcUserRequest request = new OidcUserRequest(clientRegistration, accessToken, idToken);

        Mono<OidcUser> defer = Mono.defer(() -> service.loadUser(request));
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                defer::block
        );

        assertTrue(exception.getError().getDescription().contains("hd"), "Exception should indicate hd claim problem");
    }
}
