package com.fuzzlab.lab;

/**
 * The fixed, closed DTO the secure twin's Jackson deserialization targets
 * (CC-LAB-0091's `jackson_typed_allowlist_deserialize` transform) -- no
 * polymorphism, so an attacker-supplied type hint in the request body has
 * nothing to redirect.
 */
public class PlaybackResumeRequest {
    private String profileId;
    private String eventType;
    private long positionMs;

    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public long getPositionMs() {
        return positionMs;
    }

    public void setPositionMs(long positionMs) {
        this.positionMs = positionMs;
    }
}
