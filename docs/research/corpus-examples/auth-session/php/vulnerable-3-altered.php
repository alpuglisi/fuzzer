<?php
// Manufactured third variant for auth-session/php CWE-347/CWE-757
// (Improper Verification of Cryptographic Signature / Selection of a
// Less-Secure Algorithm During Negotiation) -- distinct from this cell's
// natural pair (vulnerable-1.php/idiomatic-1.php, firebase/php-jwt's
// real dead-`$algs`-parameter bug). This one is a hand-rolled JWT
// verifier where the token's own header `alg` claim directly selects the
// verification branch, including an `alg: none` branch that performs no
// cryptographic check at all -- a different, and even more direct, way
// to end up trusting an attacker-controlled algorithm choice.
//
// Manufactured per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's
// "Per-pair mechanics". Self-contained (core PHP `hash_hmac`/`hash_equals`
// only) so it can be exercised without any external JWT package.

function b64url_decode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function b64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function make_token(array $payload, string $alg, string $secret): string
{
    $header = ['alg' => $alg, 'typ' => 'JWT'];
    $headerB64 = b64url_encode(json_encode($header));
    $payloadB64 = b64url_encode(json_encode($payload));
    $signingInput = "$headerB64.$payloadB64";
    $sig = $alg === 'none' ? '' : hash_hmac('sha256', $signingInput, $secret, true);
    return "$signingInput." . b64url_encode($sig);
}

// BUG: dispatches verification based on the token's own claimed `alg`,
// including trusting "none" as a legitimate, signature-free choice --
// an attacker who rewrites a token's header to `{"alg":"none"}` and
// strips the signature segment sails straight through.
function verify_token(string $token, string $secret): array
{
    [$headerB64, $payloadB64, $sigB64] = explode('.', $token);
    $header = json_decode(b64url_decode($headerB64), true);
    $signingInput = "$headerB64.$payloadB64";

    switch ($header['alg'] ?? null) {
        case 'none':
            // no verification performed at all
            break;
        case 'HS256':
            $expected = hash_hmac('sha256', $signingInput, $secret, true);
            $sig = b64url_decode($sigB64);
            if (!hash_equals($expected, $sig)) {
                throw new Exception('invalid signature');
            }
            break;
        default:
            throw new Exception('unsupported alg');
    }
    return json_decode(b64url_decode($payloadB64), true);
}
