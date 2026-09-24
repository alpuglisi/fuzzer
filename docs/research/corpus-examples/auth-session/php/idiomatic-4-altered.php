<?php
// Idiomatic counterpart to vulnerable-4-altered.php (auth-session/php,
// CWE-330/CWE-640). Differs only in the token-generation mechanism: a
// CSPRNG (`random_bytes`) replaces the uniqid()+rand()+md5() construction,
// with no dependency on the system clock or a non-cryptographic PRNG.

function generate_reset_token(): string
{
    return bin2hex(random_bytes(32));
}
