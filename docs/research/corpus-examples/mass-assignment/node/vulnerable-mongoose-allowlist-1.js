// Manufactured, representative of the well-documented Mongoose
// over-posting anti-pattern -- passing req.body straight into
// findByIdAndUpdate() with no field allowlist.
router.patch('/api/products/:id', async (req, res) => {
  // No allowlist: req.body could include { "price": 0.01 } or
  // { "sellerId": "<victim-seller-id>" }, fields the intended UI never
  // exposes but the API happily persists.
  const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(product);
});
