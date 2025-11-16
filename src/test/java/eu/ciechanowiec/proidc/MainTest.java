package eu.ciechanowiec.proidc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
class MainTest {

    @SuppressWarnings("InstanceVariableMayNotBeInitialized")
    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void contextLoads() {
        // Verify that the application context loads successfully
        assertNotNull(applicationContext, "Application context should not be null");

        // Verify that essential beans are available
        assertNotNull(applicationContext.getBean(SecurityConfig.class), "SecurityConfig bean should be available");
        assertNotNull(applicationContext.getBean(GatewayConfig.class), "GatewayConfig bean should be available");
        assertNotNull(applicationContext.getBean(LoginRouteConfig.class), "LoginRouteConfig bean should be available");
        assertNotNull(applicationContext.getBean(CsrfController.class), "CsrfController bean should be available");
    }
}
