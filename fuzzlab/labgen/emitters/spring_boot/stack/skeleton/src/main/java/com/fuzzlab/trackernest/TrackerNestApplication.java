package com.fuzzlab.trackernest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * TrackerNest -- fuzzlab lab-generator target (category 3, Atlassian pick).
 * Lab-only, authorized-use only; see repo root CLAUDE.md.
 *
 * <p>Per-cell controllers are generated under {@code com.fuzzlab.trackernest}
 * subpackages and discovered by Spring Boot's own component scan (the
 * package this class lives in, and everything below it) -- no central
 * route-accumulator file is needed for this stack, unlike {@code php_laravel}'s
 * {@code routes/web.php} or {@code node_express}'s {@code app.js}: a new
 * controller class becomes reachable purely by existing on the classpath
 * under this package, the same way {@code python_fastapi}'s discovery
 * scaffold avoids one via {@code pkgutil}/{@code importlib} package walking.
 */
@SpringBootApplication
public class TrackerNestApplication {
    public static void main(String[] args) {
        SpringApplication.run(TrackerNestApplication.class, args);
    }
}
