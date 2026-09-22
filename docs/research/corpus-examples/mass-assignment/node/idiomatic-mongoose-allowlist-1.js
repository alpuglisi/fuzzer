// Manufactured, representative of the well-documented Mongoose
// "findByIdAndUpdate over-posting" pattern (Mongoose's own guides warn
// against passing req.body directly). No single upstream repo cited --
// see this file's manifest entry for the pattern's public documentation.
const { pick } = require('lodash');

const ALLOWED_FIELDS = ['name', 'description', 'category'];

router.patch('/api/products/:id', async (req, res) => {
  const updates = pick(req.body, ALLOWED_FIELDS);
  const product = await Product.findByIdAndUpdate(req.params.id, updates, { new: true });
  res.json(product);
});
