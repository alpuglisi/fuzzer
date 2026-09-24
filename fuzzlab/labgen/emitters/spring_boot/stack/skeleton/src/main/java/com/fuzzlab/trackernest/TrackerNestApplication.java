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

    /**
     * This stack's own fixed, per-run shared HMAC key for its JWT-protected
     * illustrative cell (`CC-LAB-0193`, Netflix's eighth real page, this
     * stack's first `jwt_algorithm_confusion` instance) -- the same
     * "lab-only, no real secret rotation" simplification every other
     * stack's own skeleton already uses for its own fixed secret (e.g.
     * {@code go_net_http}'s own {@code jwtSecret}, {@code
     * fuzzlab/labgen/emitters/go_net_http/stack/skeleton/main.go}). Real
     * per-deployment secret management/rotation is out of this lab
     * skeleton's scope.
     */
    public static final String JWT_SECRET = "fuzzlab-spring-boot-lab-fixed-demo-jwt-secret";

    /**
     * Decodes a base64url-encoded JWT segment, tolerating the segment's own
     * usual missing `=` padding (JWT's own base64url convention is
     * unpadded) by re-padding it to a multiple of 4 characters first. Fails
     * closed, mirroring {@code go_net_http}'s own {@code
     * base64.RawURLEncoding.DecodeString} usage in {@code
     * read_authorization_bearer_token.go.j2}: a malformed segment (bad
     * characters, or a length that can never be padded to a valid base64
     * length) decodes to an empty byte array rather than throwing, so a
     * caller comparing it (e.g. via {@link java.security.MessageDigest#isEqual})
     * or hashing it always fails the comparison/produces a mismatch instead
     * of crashing the request.
     */
    public static byte[] base64UrlDecode(String segment) {
        String padded = segment;
        int remainder = padded.length() % 4;
        if (remainder == 2) {
            padded = padded + "==";
        } else if (remainder == 3) {
            padded = padded + "=";
        } else if (remainder == 1) {
            return new byte[0];
        }
        try {
            return java.util.Base64.getUrlDecoder().decode(padded);
        } catch (IllegalArgumentException ex) {
            return new byte[0];
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(TrackerNestApplication.class, args);
    }
}
