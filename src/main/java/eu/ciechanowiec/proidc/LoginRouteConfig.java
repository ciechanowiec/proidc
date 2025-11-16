package eu.ciechanowiec.proidc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * Configuration class responsible for defining the routing function for the login page.
 * This class configures a route that serves a static HTML login page when the "/login" endpoint is accessed.
 */
@Configuration
public class LoginRouteConfig {

    /**
     * Constructs a new instance of this class.
     */
    @SuppressWarnings("PMD.UnnecessaryConstructor")
    public LoginRouteConfig() {
        // For Javadoc
    }

    /**
     * Creates a {@link RouterFunction} that handles GET requests to the "/login" endpoint.
     * The function serves a static HTML login page from the configured resource.
     *
     * @param loginPageResource the resource containing the HTML login page content
     * @return {@link RouterFunction} that routes GET requests to "/login" to the login page resource
     */
    @Bean
    public RouterFunction<ServerResponse> loginRouter(@Value("${proidc.login_page}") Resource loginPageResource) {
        return RouterFunctions.route()
                .GET(
                        "/login",
                        request -> ServerResponse.ok()
                                .contentType(MediaType.TEXT_HTML)
                                .body(BodyInserters.fromResource(loginPageResource))
                ).build();
    }
}
