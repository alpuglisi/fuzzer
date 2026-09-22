<?php
// Manufactured, representative of a safe APCu-cached-session-job pattern
// (common in PHP background-processing setups that cache a pending job
// alongside a user's session for quick re-display).

function loadPendingJobFromCache(string $sessionId): ?array
{
    $raw = apcu_fetch("pending_job:{$sessionId}");
    if ($raw === false) {
        return null;
    }
    $job = json_decode($raw, true);
    return is_array($job) ? $job : null;
}
