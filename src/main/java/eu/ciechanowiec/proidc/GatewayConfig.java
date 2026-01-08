package eu.ciechanowiec.proidc;

import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Configuration class for the Spring Cloud Gateway that handles request relay and security.
 */
@Configuration
@Slf4j
@ToString
public class GatewayConfig {

    private final String idTokenHeaderName;
    private final Set<String> allHeadersToRemoveLowerCase;
    private final Set<String> allCookiesToRemoveLowerCase;

    /**
     * Constructs a new instance of this class.
     *
     * @param idTokenHeaderName the name of the header to use when forwarding the ID token
     * @param sessionCookieName the name of the session cookie, which will be removed from forwarded requests
     * @param headersToRemove   a collection of header names that should be removed from forwarded requests
     * @param cookiesToRemove   a collection of cookie names that should be removed from forwarded requests
     */
    public GatewayConfig(
            @Value("${proidc.id_token.header_name}") String idTokenHeaderName,
            @Value("${server.reactive.session.cookie.name:SESSION}") String sessionCookieName,
            @Value("${proidc.headers_to_remove}") Collection<String> headersToRemove,
            @Value("${proidc.cookies_to_remove}") Collection<String> cookiesToRemove
    ) {
        this.idTokenHeaderName = idTokenHeaderName;
        this.allHeadersToRemoveLowerCase = Stream.concat(headersToRemove.stream(), Stream.of(idTokenHeaderName))
                .map(headerToRemove -> headerToRemove.toLowerCase(Locale.getDefault()))
                .collect(Collectors.toUnmodifiableSet());
        this.allCookiesToRemoveLowerCase = Stream.concat(cookiesToRemove.stream(), Stream.of(sessionCookieName))
                .map(cookieToRemove -> cookieToRemove.toLowerCase(Locale.getDefault()))
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Creates a {@link GlobalFilter} that processes requests before they are forwarded.
     *
     * @return a {@link GlobalFilter} that processes requests before they are forwarded
     */
    @Bean
    @SuppressWarnings({"MethodLength", "LambdaBodyLength", "PMD.LooseCoupling"})
    public GlobalFilter requestRelayFilter() {
        log.trace("{} started execution", this);
        return (exchange, chain) -> {
            ServerHttpRequest requestOriginal = exchange.getRequest();
            ServerHttpRequest requestCleaned = removeSensitiveHeadersAndCookies(
                    requestOriginal
            );

            return exchange.getPrincipal()
                    .ofType(OAuth2AuthenticationToken.class)
                    .map(OAuth2AuthenticationToken::getPrincipal)
                    .ofType(OidcUser.class)
                    .map(OidcUser::getIdToken)
                    .map(OidcIdToken::getTokenValue)
                    .map(
                            idTokenHeaderValue -> {
                                log.trace("ID Token found, relaying it as a '{}' header", idTokenHeaderName);
                                ServerHttpRequest requestCleanedButWithIdToken = requestCleaned.mutate()
                                        .header(idTokenHeaderName, idTokenHeaderValue)
                                        .build();
                                return exchange.mutate().request(requestCleanedButWithIdToken).build();
                            }
                    ).defaultIfEmpty(exchange.mutate().request(requestCleaned).build())
                    .doOnSuccess(
                            finalExchange -> finalExchange.getResponse().beforeCommit(
                                    () -> {
                                        ServerHttpResponse response = finalExchange.getResponse();
                                        HttpHeaders headers = response.getHeaders();
                                        Optional.ofNullable(headers.get(HttpHeaders.LOCATION))
                                                .stream()
                                                .flatMap(Collection::stream)
                                                .filter(location -> location.startsWith("/system/sling/form/login"))
                                                .findAny()
                                                .ifPresent(
                                                        location -> {
                                                            log.trace(
                                                                    "Removing location header with value: '{}'",
                                                                    location
                                                            );
                                                            headers.remove(HttpHeaders.LOCATION);
                                                            response.setStatusCode(HttpStatus.UNAUTHORIZED);
                                                        }
                                                );
                                        return Mono.empty();
                                    }
                            )
                    ).flatMap(chain::filter)
                    .doOnSuccess(voidObject -> log.trace("{} finished execution", this));
        };
    }

    /**
     * Removes sensitive headers and cookies from the request.
     *
     * @param requestToBeCleaned the original {@link ServerHttpRequest} that needs to be cleaned
     * @return a new {@link ServerHttpRequest} with sensitive headers and cookies removed
     */
    private ServerHttpRequest removeSensitiveHeadersAndCookies(ServerHttpRequest requestToBeCleaned) {
        return requestToBeCleaned.mutate().headers(
                headers -> {
                    List<String> actualHeaderNamesToRemove = headers.keySet()
                            .stream()
                            .filter(
                                    actualHeaderName -> {
                                        String actualHeaderNameLoweCase = actualHeaderName.toLowerCase(
                                                Locale.getDefault()
                                        );
                                        return allHeadersToRemoveLowerCase.contains(actualHeaderNameLoweCase);
                                    }
                            ).toList();
                    actualHeaderNamesToRemove.forEach(headers::remove);
                    cookieHeaderWithoutSensitiveCookies(requestToBeCleaned).ifPresentOrElse(
                            newCookieValue -> headers.set(HttpHeaders.COOKIE, newCookieValue),
                            () -> headers.remove(HttpHeaders.COOKIE)
                    );
                }
        ).build();
    }

    /**
     * Creates a new {@link HttpHeaders#COOKIE} header value without sensitive cookies.
     * <p>
     * This method filters out cookies that are configured to be removed and
     * creates a new {@link HttpHeaders#COOKIE} header value with the remaining cookies.
     *
     * @param requestToBeCleaned the original {@link ServerHttpRequest} containing cookies
     * @return an {@link Optional} containing the new {@link HttpHeaders#COOKIE} header value,
     * or an empty {@link Optional} if there are no cookies left
     */
    private Optional<String> cookieHeaderWithoutSensitiveCookies(ServerHttpRequest requestToBeCleaned) {
        return Optional.of(
                requestToBeCleaned.getCookies().values().stream()
                        .flatMap(List::stream)
                        .filter(
                                cookie -> {
                                    String cookieNameLowerCase = cookie.getName().toLowerCase(Locale.getDefault());
                                    return !allCookiesToRemoveLowerCase.contains(cookieNameLowerCase);
                                }
                        ).map(cookie -> "%s=%s".formatted(cookie.getName(), cookie.getValue()))
                        .collect(Collectors.joining("; "))
        ).filter(newCookieValue -> !newCookieValue.isEmpty());
    }
}
