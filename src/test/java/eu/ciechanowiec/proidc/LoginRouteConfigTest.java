package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest
@AutoConfigureWebTestClient
class LoginRouteConfigTest {

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Autowired
    private WebTestClient webTestClient;

    @Test
    @SuppressWarnings({"PMD.UnitTestShouldIncludeAssert", "TestMethodWithoutAssertion"})
    void shouldServeLoginPage() {
        webTestClient.get()
                .uri("/login")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.TEXT_HTML);
    }
}
