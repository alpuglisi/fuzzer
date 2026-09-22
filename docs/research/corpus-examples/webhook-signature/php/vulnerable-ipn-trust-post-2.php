<?php
// Manufactured vulnerable variant, derived from
// idiomatic-paypal-ipn-verify-2.php. A well-documented real historical
// anti-pattern: processing the IPN POST body directly without the
// post-back verification step at all.
function handlePayPalIpn(array $postData): void
{
    // No call to PayPal's own IPN verification endpoint -- $postData is
    // trusted outright. Any client that knows the IPN listener URL can
    // POST a forged "payment_status=Completed" notification.
    if (($postData['payment_status'] ?? '') === 'Completed') {
        markOrderPaid($postData['invoice']);
    }
}
