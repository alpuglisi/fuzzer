<?php
// Manufactured vulnerable variant, derived from
// idiomatic-pdf-remote-image-5.php. file_get_contents() on a raw,
// unchecked URL -- a well-documented real-world PHP SSRF vector, since
// file_get_contents() transparently supports the http:// stream wrapper
// (and, unless disabled, phar://, which has its own deserialization risk).

function fetchRemoteImageForPdf(string $imageUrl): ?string
{
    // No scheme check, no IP check, follow_location left at PHP's
    // default (enabled) -- and file_get_contents() will also happily
    // open a local path or a phar:// URI here, not just http(s).
    return @file_get_contents($imageUrl) ?: null;
}
