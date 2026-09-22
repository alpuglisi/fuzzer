// Manufactured, representative of safe Nodemailer usage: recipient/
// reply-to fields are passed as structured option properties, which
// Nodemailer's own MIME builder encodes rather than raw-concatenating.
const nodemailer = require('nodemailer');

async function sendBookingConfirmation(guestName, guestEmail, specialRequests) {
  await transporter.sendMail({
    from: 'bookings@example.com',
    to: guestEmail,
    replyTo: guestEmail,
    subject: `Booking confirmed for ${guestName}`,
    text: `Special requests: ${specialRequests}`,
  });
}
