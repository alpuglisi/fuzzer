// Manufactured, representative of a safe inbound-webhook payload handler
// (JSON.parse only -- no code-execution-capable deserializer).
async function handleInboundWebhook(rawBody) {
  const event = JSON.parse(rawBody);
  await queue.add('process-webhook-event', event);
}
