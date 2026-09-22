# Manufactured, representative of safe email construction with Python's
# stdlib email.message.EmailMessage: header values are set via the
# object's own __setitem__, which rejects embedded CR/LF per RFC 5322
# folding rules rather than raw-concatenating into a header block.
from email.message import EmailMessage


def build_booking_confirmation(guest_name: str, guest_email: str, special_requests: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "bookings@example.com"
    msg["To"] = guest_email
    msg["Subject"] = f"Booking confirmed for {guest_name}"
    msg.set_content(f"Special requests: {special_requests}")
    return msg
