package com.fuzzlab.trackernest.generated;

import java.io.Serializable;

/**
 * TrackerNest's expected webhook-payload type ({@code CC-LAB-0092}) -- the
 * one class name the insecure-deserialization cell's secure twin allowlists
 * via a {@code resolveClass()} override. Checked into the skeleton (not
 * per-cell generated) since both twins reference the same fixed type.
 */
public class WebhookEvent implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String eventType;

    public WebhookEvent(String eventType) {
        this.eventType = eventType;
    }

    public String getEventType() {
        return eventType;
    }

    @Override
    public String toString() {
        return "WebhookEvent(" + eventType + ")";
    }
}
