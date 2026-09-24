<?php
// Manufactured third variant for auth-session/php CWE-330/CWE-640 (Use of
// Insufficiently Random Values / Weak Password Recovery Mechanism) --
// distinct from this cell's natural pair (vulnerable-2.php/idiomatic-2.php,
// InvoicePlane's real md5(time() . $email . salt()) bug). This one is a
// different, extremely common PHP idiom for the same weakness class:
// `uniqid(rand(), true)` hashed with md5. `uniqid()` (even in its "more
// entropy" mode) is derived from the system clock (microtime), and
// `rand()` is a non-cryptographic PRNG -- neither input is suitable for a
// security-sensitive token, regardless of hashing the result.

function generate_reset_token(): string
{
    // BUG: uniqid() is clock-derived and rand() is a non-cryptographic
    // PRNG; hashing their concatenation with md5() does not add real
    // entropy, it only obscures the (still guessable/brute-forceable)
    // inputs.
    return md5(uniqid((string) rand(), true));
}
