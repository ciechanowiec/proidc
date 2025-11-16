package eu.ciechanowiec.proidc;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Controller responsible for providing Cross-Site Request Forgery (CSRF) tokens.
 * This controller exposes an endpoint that allows clients to retrieve CSRF tokens
 * for protection against CSRF attacks.
 */
@RestController
public class CsrfController {

    /**
     * Constructs a new instance of this class.
     */
    @SuppressWarnings("PMD.UnnecessaryConstructor")
    public CsrfController() {
        // For Javadoc
    }

    /**
     * Retrieves the CSRF token associated with the current session.
     *
     * @param exchange the current {@link ServerWebExchange} which contains the {@link CsrfToken}
     * @return a {@link Mono} containing the {@link CsrfToken} if available, or an empty {@link Mono} if no token exists
     */
    @GetMapping("/csrf")
    public Mono<CsrfToken> getCsrfToken(ServerWebExchange exchange) {
        return exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
    }
}
