<?php
// Manufactured, representative of the real, historically-documented
// PayPal IPN verification pattern: the received notification is posted
// back to PayPal's own verification endpoint, which confirms it
// genuinely originated from PayPal (PayPal's own IPN integration guide
// documents exactly this "post back to verify" flow).
function verifyPayPalIpn(string $rawPostBody): bool
{
    $verifyBody = 'cmd=_notify-validate&' . $rawPostBody;

    $ch = curl_init('https://ipnpb.paypal.com/cgi-bin/webscr');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $verifyBody);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    return trim($response) === 'VERIFIED';
}
