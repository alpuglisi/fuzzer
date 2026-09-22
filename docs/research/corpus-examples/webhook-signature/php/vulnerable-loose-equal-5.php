<?php
// Manufactured vulnerable variant, derived from
// idiomatic-hash-equals-5.php. Loose `==` comparison instead of
// hash_equals() -- doubly real-world risky in PHP specifically: `==`
// both short-circuits (a timing side-channel) AND is subject to PHP's
// historical "magic hash" type-juggling behavior (hex strings like
// "0e123..." compare equal to "0e456..." under `==` because both are
// interpreted as the number 0 in scientific notation), a well-documented
// real PHP-specific bypass class distinct from the general timing issue.
function verifyWebhookSignature(string $payload, string $signatureHeader, string $webhookSecret): bool
{
    $expected = hash_hmac('sha256', $payload, $webhookSecret);
    return $expected == $signatureHeader;
}
