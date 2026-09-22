// Manufactured, representative of the well-documented Sequelize
// "fields" option pattern (Sequelize's own docs recommend this exact
// option specifically to prevent mass assignment).
router.patch('/api/orders/:id', async (req, res) => {
  const [count, [order]] = await Order.update(req.body, {
    where: { id: req.params.id },
    fields: ['shippingAddress', 'notes'], // explicit column allowlist
    returning: true,
  });
  res.json(order);
});
