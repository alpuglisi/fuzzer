<?php
// Manufactured, representative of safe generic HMAC webhook-signature
// verification in PHP: hash_equals() performs a constant-time
// comparison -- PHP's own documentation for hash_equals() states it was
// added specifically to compare user-supplied strings against a known
// hash without leaking timing information.
function verifyWebhookSignature(string $payload, string $signatureHeader, string $webhookSecret): bool
{
    $expected = hash_hmac('sha256', $payload, $webhookSecret);
    return hash_equals($expected, $signatureHeader);
}
