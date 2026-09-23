<?php

namespace App\Support;

/**
 * Insecure-deserialization real magic-method proof gadget (`CC-LAB-0220`,
 * CircleFeed's fourth and final designed cell, category 2's Facebook pick
 * -- see docs/research/category2-social-ugc-functionality-and-cwe-
 * research.md sec 5 row 4 / sec 6 row 4).
 *
 * A single-shot PHP analogue of `CC-LAB-0097`'s pickle `__reduce__` proof:
 * `__wakeup()` is PHP's own documented magic method that `unserialize()`
 * invokes immediately after reconstructing an object (the same hook every
 * real-world PHP unserialize-RCE POP-gadget chain ultimately calls into --
 * this class just skips the chain and provides the terminal side effect
 * directly, since no gadget chain is needed to demonstrate the underlying
 * bug this cell targets).
 *
 * Deliberately a real, checked-in class inside the booted app's own `App\`
 * PSR-4 autoload root (`app/Support/`), not a class defined only in a test
 * file -- a class `unserialize()` cannot resolve inside the real booted
 * subprocess is exactly the mistake `CC-LAB-0097`'s own pickle proof had to
 * avoid for Python (there, a `__reduce__` target had to be stdlib-
 * resolvable rather than defined in the test module, since the booted
 * subprocess has no access to this repo's test files at all -- the same
 * constraint here, solved the PHP way: putting the class inside the
 * generated app's own autoload path instead of reaching for a stdlib
 * class).
 *
 * Writes a real, checkable marker file when unserialized -- the standard,
 * unambiguous way to prove `unserialize()` genuinely executed
 * attacker-chosen code, not merely that it returned an object.
 */
class MarkerWriteGadget
{
    public string $markerPath = '';
    public string $markerContents = 'pwned';

    public function __wakeup(): void
    {
        if ($this->markerPath !== '') {
            file_put_contents($this->markerPath, $this->markerContents);
        }
    }
}
