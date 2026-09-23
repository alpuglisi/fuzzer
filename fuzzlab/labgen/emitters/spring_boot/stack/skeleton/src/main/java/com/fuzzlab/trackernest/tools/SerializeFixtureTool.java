package com.fuzzlab.trackernest.tools;

import com.fuzzlab.trackernest.generated.UnexpectedType;
import com.fuzzlab.trackernest.generated.WebhookEvent;

import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Test-only helper ({@code CC-LAB-0132}): writes a real Java-serialization-
 * protocol byte stream for one of the two fixed support classes to stdout,
 * so the insecure-deserialization cell's live-boot test can produce real
 * fixture payloads without Python needing to emit Java's serialization wire
 * format itself. Never invoked by the running Spring Boot app -- plain
 * {@code main()}, no Spring dependency, present on the classpath (and
 * compiled by the same {@code mvn package} that compiles everything else)
 * but not a controller/bean of any kind.
 *
 * <p>Usage: {@code java -cp target/classes
 * com.fuzzlab.trackernest.tools.SerializeFixtureTool <WebhookEvent|UnexpectedType> <marker>}
 */
public final class SerializeFixtureTool {
    private SerializeFixtureTool() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: SerializeFixtureTool <WebhookEvent|UnexpectedType> <marker>");
            System.exit(1);
        }
        String className = args[0];
        String marker = args[1];
        Serializable payload;
        if (className.equals("WebhookEvent")) {
            payload = new WebhookEvent(marker);
        } else if (className.equals("UnexpectedType")) {
            payload = new UnexpectedType(marker);
        } else {
            System.err.println("unknown class: " + className);
            System.exit(1);
            return;
        }
        try (ObjectOutputStream oos = new ObjectOutputStream(System.out)) {
            oos.writeObject(payload);
            oos.flush();
        }
    }
}
