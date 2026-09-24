<?php
// Idiomatic counterpart to vulnerable-session-role-recheck-1-altered.php
// (auth-session/php, CWE-287/CWE-613/CWE-863). Differs only in the
// authorization mechanism: the current, authoritative role is re-fetched
// (here via an injected callback standing in for a database lookup) on
// every call instead of trusting the value captured into $_SESSION at
// login time, so a mid-session privilege downgrade takes effect
// immediately rather than only after the session ends.

function require_admin(array $session, callable $fetch_current_role): void
{
    $currentRole = $fetch_current_role($session['user_id'] ?? null);
    if ($currentRole !== 'admin') {
        throw new Exception('forbidden');
    }
}
