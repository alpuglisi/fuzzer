// idiomatic-4-altered.js
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". Gift-card redemption at checkout -- a distinct sub-scenario
// from this file's Stripe-charge-amount pairs (vulnerable-1/2/3.js,
// idiomatic-1/2.js): here the trust boundary is what amount of a stored
// GiftCard balance gets applied as store credit, not the charge amount
// itself. The amount actually redeemed is always recomputed server-side
// from the GiftCard record's own stored balance, clamped to the cart's
// own computed total -- never taken from whatever the client claims to
// want redeemed.
const express = require('express');
const router = express.Router();
const GiftCard = require('../models/GiftCard');
const Cart = require('../models/Cart');

router.post('/checkout/redeem-gift-card', async (req, res) => {
  const { cartId, code } = req.body;
  const cart = await Cart.findById(cartId).populate('items.product');
  if (!cart) return res.status(404).json({ error: 'cart not found' });

  const giftCard = await GiftCard.findOne({ code, active: true });
  if (!giftCard) return res.status(404).json({ error: 'invalid gift card' });

  const cartTotal = cart.items.reduce(
    (sum, item) => sum + item.product.price * item.quantity,
    0
  );

  // The amount actually redeemed is the smaller of the card's own stored
  // balance and the cart's own computed total -- never a client-supplied
  // number.
  const redeemAmount = Math.min(giftCard.balanceCents, Math.round(cartTotal * 100));

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
