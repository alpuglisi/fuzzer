// Manufactured, representative of safe Node HTTP header usage: Node's
// own http module has rejected embedded CR/LF in header VALUES passed to
// res.setHeader() since Node 10 (throws ERR_INVALID_CHAR) -- this entry
// shows the additional common mitigation layer of validating the value's
// shape before it ever reaches setHeader().
function setBookingIdCookie(res, bookingId) {
  if (!/^[A-Za-z0-9-]+$/.test(bookingId)) {
    throw new Error('Invalid booking id');
  }
  res.setHeader('Set-Cookie', `bookingId=${bookingId}; HttpOnly; Secure`);
}
