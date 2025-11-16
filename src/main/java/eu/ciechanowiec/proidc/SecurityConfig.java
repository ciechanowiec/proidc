package eu.ciechanowiec.proidc;

import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Configuration class for {@link ServerHttpSecurity}
 * that defines security filter chains and authentication mechanisms.
 */
@Slf4j
@Configuration
@ToString
public class SecurityConfig {

    private final String upstreamLogoutUrl;
    private final String idTokenHeaderName;
    private final String regexForExpectedHD;
    private final Collection<String> patternsOfPathsToBlock;

    /**
     * Constructs a new instance of {@link SecurityConfig} with the specified configuration parameters.
     *
     * @param upstreamLogoutUrl      the URL of the upstream server's logout endpoint
     * @param idTokenHeaderName      the name of the header to use when sending the
     *                               {@link OidcIdToken}
     *                               to the upstream server
     * @param regexForExpectedHD     a regular expression {@link Pattern} that valid hosted domain values must match
     * @param patternsOfPathsToBlock a {@link Collection} of path patterns that should be blocked from access
     */
    SecurityConfig(
            @Value("${proidc.upstream_logout_uri}") String upstreamLogoutUrl,
            @Value("${proidc.id_token.header_name}") String idTokenHeaderName,
            @Value("${proidc.expected_hosted_domain.regex}") String regexForExpectedHD,
            @Value("${proidc.paths_to_block.patterns}") Collection<String> patternsOfPathsToBlock
    ) {
        this.upstreamLogoutUrl = upstreamLogoutUrl;
        this.idTokenHeaderName = idTokenHeaderName;
        this.regexForExpectedHD = regexForExpectedHD;
        this.patternsOfPathsToBlock = Collections.unmodifiableCollection(patternsOfPathsToBlock);
        log.info("Initialized {}", this);
    }

    /**
     * Creates a {@link SecurityWebFilterChain} that denies access to restricted paths.
     *
     * @param http {@link ServerHttpSecurity} to configure
     * @return {@link SecurityWebFilterChain} that denies access to restricted paths
     */
    @Bean
    @Order(1)
    public SecurityWebFilterChain restrictedPathsDenyFilterChain(ServerHttpSecurity http) {
        ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
        URI redirectUri = URI.create("/");
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(patternsOfPathsToBlock.toArray(String[]::new)))
                .authorizeExchange(exchange -> exchange.anyExchange().denyAll())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(
                                (exchange, authenticationException)
                                        -> redirectStrategy.sendRedirect(exchange, redirectUri)
                        )
                        .accessDeniedHandler(
                                (exchange, authenticationException)
                                        -> redirectStrategy.sendRedirect(exchange, redirectUri)
                        )
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    /**
     * Creates a {@link SecurityWebFilterChain} that denies direct access to the logout endpoint.
     *
     * @param http {@link ServerHttpSecurity} to configure
     * @return {@link SecurityWebFilterChain} that denies direct access to the logout endpoint
     */
    @Bean
    @Order(2)
    public SecurityWebFilterChain logoutDenyFilterChain(ServerHttpSecurity http) {
        ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
        URI redirectUri = URI.create("/");
        return http.securityMatcher(ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/logout"))
                .authorizeExchange(exchange -> exchange.anyExchange().denyAll())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(
                                (exchange, authenticationException)
                                        -> redirectStrategy.sendRedirect(exchange, redirectUri)
                        )
                        .accessDeniedHandler(
                                (exchange, authenticationException)
                                        -> redirectStrategy.sendRedirect(exchange, redirectUri)
                        )
                ).build();
    }

    /**
     * Creates the main {@link SecurityWebFilterChain} that configures authentication and authorization.
     *
     * @param http                 {@link ServerHttpSecurity} to configure
     * @param logoutSuccessHandler {@link ServerLogoutSuccessHandler} to use for successful logout events
     * @return {@link SecurityWebFilterChain} that configures authentication and authorization
     */
    @Bean
    @Order(3)
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http, ServerLogoutSuccessHandler logoutSuccessHandler
    ) {
        http.authorizeExchange(
                        exchange ->
                                exchange.pathMatchers("/login")
                                        .permitAll()
                                        .anyExchange()
                                        .authenticated()
                ).oauth2Login(oauth2 -> oauth2.loginPage("/login"))
                .logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler))
                .csrf(csrf -> csrf.csrfTokenRepository(new CookieServerCsrfTokenRepository()));
        return http.build();
    }

    /**
     * Creates a {@link ServerLogoutSuccessHandler} that notifies an upstream server about logout events.
     *
     * @param repository       {@link ReactiveClientRegistrationRepository} for OIDC providers
     * @param webClientBuilder {@link WebClient.Builder} for creating {@link WebClient} instances
     * @return {@link ServerLogoutSuccessHandler} that handles logout success events
     */
    @Bean
    public ServerLogoutSuccessHandler logoutSuccessHandler(
            ReactiveClientRegistrationRepository repository, WebClient.Builder webClientBuilder
    ) {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(repository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        HttpClient httpClient = HttpClient.create().followRedirect(false);
        WebClient webClient = webClientBuilder.clientConnector(new ReactorClientHttpConnector(httpClient)).build();
        return new UpstreamServerLogoutSuccessHandler(
                webClient,
                upstreamLogoutUrl,
                idTokenHeaderName,
                oidcLogoutSuccessHandler
        );
    }

    /**
     * Creates a custom {@link OidcReactiveOAuth2UserService} that validates the hosted domain claim.
     *
     * @return {@link ReactiveOAuth2UserService} that validates {@link OidcUser}s
     */
    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        ReactiveOAuth2UserService<OidcUserRequest, OidcUser> delegate = new OidcReactiveOAuth2UserService();
        Pattern hdClaimRegexPattern = Pattern.compile(regexForExpectedHD);
        return userRequest -> delegate.loadUser(userRequest)
                .flatMap(
                        oidcUser -> {
                            String actualHD = Optional.ofNullable(oidcUser.getClaimAsString("hd"))
                                    .orElse(StringUtils.EMPTY);
                            Matcher matcher = hdClaimRegexPattern.matcher(actualHD);
                            if (matcher.matches()) {
                                return Mono.just(oidcUser);
                            }
                            OAuth2Error error = new OAuth2Error(
                                    "invalid_token",
                                    "The 'hd' claim '%s' is not allowed.".formatted(actualHD),
                                    "https://developers.google.com/identity/protocols/oauth2/openid-connect#hd-param"
                            );
                            String errorMessage = error.toString();
                            return Mono.error(new OAuth2AuthenticationException(error, errorMessage));
                        }
                );
    }
}
