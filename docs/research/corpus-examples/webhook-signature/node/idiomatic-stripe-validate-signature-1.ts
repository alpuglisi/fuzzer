// Excerpt of stripe-node, src/Webhooks.ts (MIT). Source: repo
// stripe/stripe-node, commit 9996a2d4f129c8b02f36f715b27a30c956087007.

function validateComputedSignature(
  payload: string,
  header: string,
  details: WebhookParsedHeader,
  expectedSignature: string,
  tolerance: number,
  suspectPayloadType: boolean,
  secretContainsWhitespace: boolean,
  receivedAt?: number
): boolean {
  const signatureFound = !!details.signatures.filter(
    platformFunctions.secureCompare.bind(platformFunctions, expectedSignature)
  ).length;

  if (!signatureFound) {
    throw new StripeSignatureVerificationError(header, payload, {
      message: 'No signatures found matching the expected signature for payload.',
    });
  }

  const timestampAge =
    Math.floor((typeof receivedAt === 'number' ? receivedAt : Date.now()) / 1000) -
    details.timestamp;

  if (tolerance > 0 && timestampAge > tolerance) {
    throw new StripeSignatureVerificationError(header, payload, {
      message: 'Timestamp outside the tolerance zone',
    });
  }

  return true;
}
