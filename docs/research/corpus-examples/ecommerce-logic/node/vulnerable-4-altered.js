// vulnerable-4-altered.js
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" -- derived from idiomatic-4-altered.js's own real structure,
// altered ONLY in how the redeemed amount is decided: the client's own
// posted `amountCents` field is trusted outright instead of recomputing it
// from the GiftCard record's stored balance. Everything else (the models
// used, the response shape, the surrounding route) is unchanged, per this
// corpus's minimal-pair discipline.
const express = require('express');
const router = express.Router();
const GiftCard = require('../models/GiftCard');
const Cart = require('../models/Cart');

router.post('/checkout/redeem-gift-card', async (req, res) => {
  const { cartId, code, amountCents } = req.body;
  const cart = await Cart.findById(cartId).populate('items.product');
  if (!cart) return res.status(404).json({ error: 'cart not found' });

  const giftCard = await GiftCard.findOne({ code, active: true });
  if (!giftCard) return res.status(404).json({ error: 'invalid gift card' });

  const cartTotal = cart.items.reduce(
    (sum, item) => sum + item.product.price * item.quantity,
    0
  );

  // Business-logic flaw: the amount redeemed is whatever the client claims
  // in amountCents, not the card's own stored balance and not clamped to
  // the cart's own computed total. A negative amountCents even flips the
  // subtraction below into an increase of the card's own balance.
  const redeemAmount = amountCents;

  giftCard.balanceCents -= redeemAmount;
  await giftCard.save();

  cart.appliedCreditCents = (cart.appliedCreditCents || 0) + redeemAmount;
  await cart.save();

  res.json({
    redeemedCents: redeemAmount,
    remainingBalanceCents: giftCard.balanceCents,
    newTotalCents: Math.round(cartTotal * 100) - cart.appliedCreditCents,
  });
});

module.exports = router;
