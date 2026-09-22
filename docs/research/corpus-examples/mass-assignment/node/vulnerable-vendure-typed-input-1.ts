// Manufactured vulnerable variant, derived from
// idiomatic-vendure-typed-input-1.ts (Vendure, GPL-3.0). Illustrates the
// contrast: a REST admin endpoint (not GraphQL) added alongside Vendure's
// typed-input API that merges the raw request body directly onto the
// loaded entity, losing the GraphQL schema's implicit allowlist.
// License note: derived from GPL-3.0 code -- same caution as the
// idiomatic entry's license note.

app.patch('/admin-api/products/:id', async (req, res) => {
  const product = await connection.getEntityOrThrow(Product, req.params.id);

  // No typed input DTO -- every key in req.body is applied, including
  // fields the GraphQL schema would never expose for direct update
  // (e.g. `enabled`, `channelIds`, internal pricing fields).
  Object.assign(product, req.body);
  await connection.getRepository(Product).save(product);

  res.json(product);
});
