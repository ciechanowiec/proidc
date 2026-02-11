package eu.ciechanowiec.proidc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Optional;

/**
 * Controller responsible for providing Cross-Site Request Forgery (CSRF) tokens.
 * This controller exposes an endpoint that allows clients to retrieve CSRF tokens
 * for protection against CSRF attacks.
 */
@RestController
public class CsrfController {

    private static final String XSRF_TOKEN_COOKIE_NAME = "XSRF-TOKEN";
    private final Duration cookieMaxAge;

    /**
     * Constructs a new instance of this class.
     *
     * @param cookieMaxAge the maximum age for the CSRF token cookie
     */
    public CsrfController(
            @Value("${server.reactive.session.cookie.max-age}") Duration cookieMaxAge
    ) {
        this.cookieMaxAge = cookieMaxAge;
    }

    /**
     * Retrieves the CSRF token associated with the current session and sets the XSRF-TOKEN cookie.
     *
     * @param exchange the current {@link ServerWebExchange} which contains the {@link CsrfToken}
     * @return a {@link Mono} containing the {@link CsrfToken} if available
     */
    @GetMapping("/csrf")
    public Mono<CsrfToken> getCsrfToken(ServerWebExchange exchange) {
        Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
        return csrfToken.doOnSuccess(
                tokenNullable -> Optional.ofNullable(tokenNullable).ifPresent(token -> setXSRFCookieAge(exchange))
        );
    }

    private void setXSRFCookieAge(ServerWebExchange exchange) {
        Optional.ofNullable(exchange.getResponse().getCookies().getFirst(XSRF_TOKEN_COOKIE_NAME)).ifPresent(
                existingCookie -> {
                    ResponseCookie cookie = ResponseCookie.from(XSRF_TOKEN_COOKIE_NAME, existingCookie.getValue())
                            .maxAge(cookieMaxAge)
                            .domain(existingCookie.getDomain())
                            .path(Optional.ofNullable(existingCookie.getPath()).orElse("/"))
                            .secure(existingCookie.isSecure())
                            .httpOnly(existingCookie.isHttpOnly())
                            .sameSite(existingCookie.getSameSite())
                            .build();
                    exchange.getResponse().getCookies().set(XSRF_TOKEN_COOKIE_NAME, cookie);
                }
        );
    }
}
