# Manufactured vulnerable variant, derived from
# idiomatic-emailmessage-structured-3.py. Raw f-string header block
# instead of EmailMessage's own header setters, then sent via smtplib's
# raw sendmail() with the pre-built string.
import smtplib


def send_booking_confirmation(guest_name: str, guest_email: str, special_requests: str) -> None:
    # No CR/LF stripping -- unlike EmailMessage's __setitem__, an
    # f-string does not validate header-folding rules at all.
    message = (
        f"From: bookings@example.com\r\n"
        f"To: {guest_email}\r\n"
        f"Subject: Booking confirmed for {guest_name}\r\n"
        f"\r\n"
        f"Special requests: {special_requests}\r\n"
    )
    with smtplib.SMTP("localhost") as server:
        server.sendmail("bookings@example.com", [guest_email], message)
