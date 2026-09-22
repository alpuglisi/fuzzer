// Manufactured, representative of the well-documented Sequelize
// mass-assignment anti-pattern -- omitting the `fields` option.
router.patch('/api/orders/:id', async (req, res) => {
  // No `fields` allowlist: req.body can set "status": "paid" or
  // "total": 0 directly, columns the order's normal lifecycle would
  // otherwise only change server-side.
  const [count, [order]] = await Order.update(req.body, {
    where: { id: req.params.id },
    returning: true,
  });
  res.json(order);
});
