<?php
// Manufactured vulnerable variant, derived from
// idiomatic-apcu-session-json-5.php. unserialize() on a cache entry keyed
// by a client-supplied session ID -- if the cache key or value is ever
// attacker-influenceable (a shared cache, a predictable/guessable
// session-id-derived key, or a cache-poisoning bug elsewhere), this
// reconstructs arbitrary PHP objects.

function loadPendingJobFromCache(string $sessionId): ?array
{
    $raw = apcu_fetch("pending_job:{$sessionId}");
    if ($raw === false) {
        return null;
    }
    // No __PHP_Incomplete_Class guard, no allowed_classes restriction --
    // unserialize()'s own second-argument allowlist (added specifically
    // to mitigate this class of bug) is not used at all.
    return unserialize($raw);
}
