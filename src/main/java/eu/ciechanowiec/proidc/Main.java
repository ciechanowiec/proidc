package eu.ciechanowiec.proidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class that serves as the entry point for the
 * {@link SpringBootApplication}.
 */
@SpringBootApplication
@SuppressWarnings("PMD.UseUtilityClass")
public class Main {

    /**
     * Constructs a new instance of this class.
     */
    @SuppressWarnings("PMD.UnnecessaryConstructor")
    public Main() {
        // For Javadoc
    }

    /**
     * The main method that bootstraps and launches the Spring Boot application.
     *
     * @param args command line arguments passed to the application
     */
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}
