package com.fuzzlab.trackernest.generated;

/**
 * The fixed, closed DTO the secure twin's Jackson deserialization targets
 * (jackson_typed_allowlist_deserialize) -- no polymorphism, so an
 * attacker-supplied type hint in the request body has nothing to redirect.
 * Ported from java_spring_boot's original PlaybackResumeRequest (CC-LAB-0171)
 * as part of the §9.2a Java/Spring Boot consolidation (CC-LAB-0173).
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
