<?php
// Manufactured third variant for auth-session/php CWE-287/CWE-613/CWE-863
// (Improper Authentication / Insufficient Session Expiration / Incorrect
// Authorization) -- distinct from this cell's natural pair
// (idiomatic-firefly-blocked-check-1.php/vulnerable-firefly-blocked-check-1.php,
// Firefly III's real per-request *blocked-account* re-check). This one
// targets a different, equally common scenario under the same CWE tuple:
// a *privilege downgrade* (e.g. an admin demoted to a regular user, or
// stripped of a specific permission) that a plain-PHP-session-based
// authorization check never notices, because the role was captured once
// into $_SESSION at login and is trusted verbatim on every later request
// -- a different framework idiom (bare $_SESSION reads, no middleware
// layer) from the natural pair's Laravel Authenticate middleware.
//
// Manufactured per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's
// "Per-pair mechanics".

// BUG: authorization is decided purely from the role snapshotted into
// $_SESSION at login time; nothing here re-consults the current,
// authoritative role (e.g. a database row an admin panel just changed).
// A user demoted from 'admin' to 'user' mid-session keeps admin access
// until they log out or the session naturally expires.
function require_admin(array $session): void
{
    if (($session['role'] ?? null) !== 'admin') {
        throw new Exception('forbidden');
    }
    // no re-check against the current, authoritative role
}
