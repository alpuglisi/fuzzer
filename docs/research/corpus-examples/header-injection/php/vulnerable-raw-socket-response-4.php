<?php
// Manufactured vulnerable variant, derived from
// idiomatic-http-header-filtered-4.php. PHP's built-in header() function
// has rejected embedded newlines since 5.1.2 -- this entry represents the
// real, still-current residual case: a hand-rolled response writer (a
// lightweight custom HTTP server, or a raw socket response built for a
// long-polling/SSE endpoint) that bypasses header() entirely and writes
// the response line-by-line itself.
function writeRawRedirectResponse($socket, string $bookingId): void
{
    // No newline stripping, and this bypasses header()'s own built-in
    // CRLF rejection entirely by writing to the socket directly.
    fwrite($socket, "HTTP/1.1 302 Found\r\n");
    fwrite($socket, "Location: /receipts/{$bookingId}\r\n");
    fwrite($socket, "\r\n");
}
