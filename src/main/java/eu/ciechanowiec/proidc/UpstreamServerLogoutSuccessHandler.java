package eu.ciechanowiec.proidc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Implementation of {@link ServerLogoutSuccessHandler} that notifies an upstream server
 * about the logout event before delegating to another logout success handler.
 */
@Slf4j
@SuppressWarnings("TypeName")
public class UpstreamServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

    private final WebClient webClient;
    private final String upstreamLogoutUrl;
    private final String idTokenHeaderName;
    private final ServerLogoutSuccessHandler delegate;

    /**
     * Constructs a new instance of this class.
     *
     * @param webClient         {@link WebClient} used to make HTTP requests to the upstream server
     * @param upstreamLogoutUrl URL of the upstream server's logout endpoint
     * @param idTokenHeaderName name of the header to use when sending the
     *                          {@link OidcIdToken} to the upstream server
     * @param delegate          {@link ServerLogoutSuccessHandler} success handler to delegate to after notifying
     *                          the upstream server
     */
    UpstreamServerLogoutSuccessHandler(WebClient webClient,
                                       String upstreamLogoutUrl,
                                       String idTokenHeaderName,
                                       ServerLogoutSuccessHandler delegate) {
        this.webClient = webClient;
        this.upstreamLogoutUrl = upstreamLogoutUrl;
        this.idTokenHeaderName = idTokenHeaderName;
        this.delegate = delegate;
    }

    /**
     * Handles a successful logout by notifying an upstream server and then delegating
     * to another logout success handler.
     *
     * @param exchange       {@link WebFilterExchange} containing the request and response
     * @param authentication {@link Authentication} that was used to authenticate the user
     * @return a Mono that completes when the logout process is complete
     */
    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        return Mono.just(authentication)
                .filter(OAuth2AuthenticationToken.class::isInstance)
                .cast(OAuth2AuthenticationToken.class)
                .map(OAuth2AuthenticationToken::getPrincipal)
                .filter(OidcUser.class::isInstance)
                .cast(OidcUser.class)
                .map(OidcUser::getIdToken)
                .map(OidcIdToken::getTokenValue)
                .flatMap(this::callUpstream)
                .doOnSuccess(aVoid -> log.debug("Successfully called upstream logout URL"))
                .onErrorResume(
                        exception -> {
                            log.error("Failed to call upstream logout URL", exception);
                            // Continue with OIDC logout even if upstream call fails
                            return Mono.empty();
                        }
                ).then(delegate.onLogoutSuccess(exchange, authentication));
    }

    /**
     * Calls the upstream server's logout endpoint with the
     * {@link OidcIdToken}.
     *
     * @param idTokenHeaderValue the value of the {@link OidcIdToken}
     *                           to send to the upstream server
     * @return a {@link Mono} that completes when the upstream server call is complete
     */
    private Mono<Void> callUpstream(String idTokenHeaderValue) {
        log.trace("Calling upstream logout URL with ID token");
        return webClient.post()
                .uri(upstreamLogoutUrl)
                .header(idTokenHeaderName, idTokenHeaderValue)
                .retrieve()
                .toBodilessEntity()
                .then();
    }
}
