<?php
// Manufactured vulnerable variant, derived from
// idiomatic-webhook-verify-3.php. No scheme/IP check, and redirects are
// followed by cURL's default.

function verifyWebhookUrl(string $callbackUrl): bool
{
    $ch = curl_init($callbackUrl);
    // FOLLOWLOCATION left at cURL's own default (false, but the app's
    // wrapper elsewhere routinely turns it on for "convenience" on every
    // other cURL call in this codebase -- see notes) and no IP/scheme
    // check at all before the request is made.
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $status >= 200 && $status < 300;
}
