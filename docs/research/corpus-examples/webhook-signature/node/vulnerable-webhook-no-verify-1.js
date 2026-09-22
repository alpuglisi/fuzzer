// Manufactured vulnerable variant, derived from
// idiomatic-stripe-validate-signature-1.ts. A well-documented real
// anti-pattern: trusting the webhook body outright because the request
// arrived over HTTPS, without calling the payment provider's own
// signature-verification API at all.
app.post('/webhooks/payment-provider', express.json(), (req, res) => {
  // No stripe.webhooks.constructEvent()-equivalent call, no signature
  // header checked at all -- anyone who discovers this URL can POST a
  // forged "payment_intent.succeeded" event and have it processed as
  // genuine.
  const event = req.body;
  fulfillOrder(event.data.object);
  res.sendStatus(200);
});
