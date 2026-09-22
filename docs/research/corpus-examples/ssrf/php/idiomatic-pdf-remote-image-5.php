<?php
// Manufactured, representative of a "generate a PDF invoice/booking
// confirmation with a remote image" feature (DomPDF/wkhtmltopdf-style
// generators fetch <img src="..."> URLs server-side while rendering).

function fetchRemoteImageForPdf(string $imageUrl): ?string
{
    $parts = parse_url($imageUrl);
    if (($parts['scheme'] ?? '') !== 'https') {
        return null;
    }

    $ip = gethostbyname($parts['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return null;
    }

    $context = stream_context_create(['http' => ['timeout' => 3, 'follow_location' => 0]]);
    return @file_get_contents($imageUrl, false, $context) ?: null;
}
