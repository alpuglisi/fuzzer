// Manufactured vulnerable variant, derived from
// idiomatic-setheader-validated-5.js. Node's res.setHeader() rejects
// embedded CR/LF at the http-module level -- this entry represents the
// real residual case: a raw socket.write() used for a custom protocol
// upgrade/WebSocket handshake response, which bypasses the http module's
// header validation entirely.
function writeRawUpgradeResponse(socket, bookingId) {
  // No character validation, and this writes directly to the TCP
  // socket, bypassing setHeader()'s own built-in CR/LF rejection.
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\n` +
    `Set-Cookie: bookingId=${bookingId}; HttpOnly\r\n` +
    `\r\n`
  );
}
