// Manufactured, representative of the well-documented, publicly disclosed
// node-serialize vulnerability class (CVE-2017-5941): the package's
// unserialize() executes any value shaped as a serialized JavaScript
// function (an IIFE embedded in the payload string) during
// deserialization, not just plain data.
const serialize = require('node-serialize');

async function handleInboundWebhook(rawBody) {
  // node-serialize's own README documented this exact risk after
  // CVE-2017-5941: a payload like
  //   {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
  // executes the embedded function during unserialize().
  const event = serialize.unserialize(rawBody);
  await queue.add('process-webhook-event', event);
}
