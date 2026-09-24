<?php
// Idiomatic counterpart to vulnerable-3-altered.php (auth-session/php,
// CWE-347/CWE-757). Differs only in the verification mechanism: the
// caller pins the one algorithm this verifier will ever accept (HS256)
// before looking at the token at all, so a token's own `alg` claim
// (including "none") can never select a weaker or absent check.

function b64url_decode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function b64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function make_token(array $payload, string $secret): string
{
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $headerB64 = b64url_encode(json_encode($header));
    $payloadB64 = b64url_encode(json_encode($payload));
    $signingInput = "$headerB64.$payloadB64";
    $sig = hash_hmac('sha256', $signingInput, $secret, true);
    return "$signingInput." . b64url_encode($sig);
}

const EXPECTED_ALG = 'HS256'; // pinned by the caller, not read from the token

function verify_token(string $token, string $secret): array
{
    [$headerB64, $payloadB64, $sigB64] = explode('.', $token);
    $header = json_decode(b64url_decode($headerB64), true);
    if (($header['alg'] ?? null) !== EXPECTED_ALG) {
        throw new Exception('rejected: expected alg ' . EXPECTED_ALG . ', token claims ' . ($header['alg'] ?? 'null'));
    }
    $signingInput = "$headerB64.$payloadB64";
    $expected = hash_hmac('sha256', $signingInput, $secret, true);
    $sig = b64url_decode($sigB64);
    if (!hash_equals($expected, $sig)) {
        throw new Exception('invalid signature');
    }
    return json_decode(b64url_decode($payloadB64), true);
}
