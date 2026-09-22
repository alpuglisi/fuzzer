<?php
// Manufactured, representative of a "verify this webhook callback URL is
// reachable" feature (common in SaaS/collaboration integration setup
// flows -- the platform pings a customer-supplied URL before saving it).

function verifyWebhookUrl(string $callbackUrl): bool
{
    $parts = parse_url($callbackUrl);
    if (!in_array($parts['scheme'] ?? '', ['https'], true)) {
        throw new InvalidArgumentException('Callback URL must use https');
    }

    $ip = gethostbyname($parts['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new InvalidArgumentException('Callback URL must not resolve to a private/reserved address');
    }

    $ch = curl_init($callbackUrl);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // no redirect chasing
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $body = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $status >= 200 && $status < 300;
}
