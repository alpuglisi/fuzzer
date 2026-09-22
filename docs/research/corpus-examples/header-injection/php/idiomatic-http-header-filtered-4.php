<?php
// Manufactured, representative of safe HTTP response header construction:
// PHP's own header() function has, since PHP 5.1.2, rejected embedded
// newlines in its argument by default -- but this entry shows the
// additional common real mitigation layer (an explicit allowlist on the
// redirect target) teams add on top of that runtime protection.
function redirectToBookingReceipt(string $bookingId): void
{
    if (!preg_match('/^[A-Za-z0-9\-]+$/', $bookingId)) {
        throw new InvalidArgumentException('Invalid booking id');
    }
    header('Location: /receipts/' . $bookingId);
}
