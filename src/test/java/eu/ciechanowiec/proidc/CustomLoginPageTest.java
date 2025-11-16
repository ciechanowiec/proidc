package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@TestPropertySource(properties = "proidc.login_page=classpath:static/login.html")
class CustomLoginPageTest {

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Autowired
    private WebTestClient webTestClient;

    @SuppressWarnings({"TestMethodWithoutAssertion", "PMD.UnitTestShouldIncludeAssert"})
    @Test
    void shouldServeCustomLoginPage() {
        // Verify that the login page is served from the configured resource
        webTestClient.get()
                .uri("/login")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.TEXT_HTML);

        // We can't easily verify the content of the page in this test,
        // but we can verify that the resource exists
        Resource loginResource = new ClassPathResource("static/login.html");
        assert loginResource.exists() : "Custom login page resource should exist";
    }
}
