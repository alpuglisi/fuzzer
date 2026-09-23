package com.fuzzlab.trackernest.generated;

import java.io.Serializable;

/**
 * A second, legitimately-{@link Serializable} but unexpected type
 * ({@code CC-LAB-0132}) -- stands in for whatever a real gadget-chain class
 * would be in a real deserialization attack, without actually including one
 * (no dangerous method bodies; this class does nothing but hold a string).
 * The insecure-deserialization cell's vulnerable twin will happily
 * construct this when its serialized bytes are handed to an unrestricted
 * {@code ObjectInputStream}, even though the endpoint only ever intends to
 * accept a {@link WebhookEvent}; the secure twin's allowlist rejects it.
 */
public class UnexpectedType implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String marker;

    public UnexpectedType(String marker) {
        this.marker = marker;
    }

    @Override
    public String toString() {
        return "UnexpectedType(" + marker + ")";
    }
}
