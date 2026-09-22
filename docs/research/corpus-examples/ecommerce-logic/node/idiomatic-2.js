// Excerpt from routes/index.js -- the add-to-cart handler (which derives
// item price from the DB product, never from client input) and the
// checkout handler (which charges cart.totalCost, a value accumulated
// server-side from product.price, never a client-supplied amount).
// See manifest.yaml for the full source file path and commit.

const express = require("express");
const csrf = require("csurf");
const stripe = require("stripe")(process.env.STRIPE_PRIVATE_KEY);
const Product = require("../models/product");
const Cart = require("../models/cart");
const Order = require("../models/order");
const middleware = require("../middleware");
const router = express.Router();

const csrfProtection = csrf();
router.use(csrfProtection);

// GET: add a product to the shopping cart when "Add to cart" button is pressed
router.get("/add-to-cart/:id", async (req, res) => {
  const productId = req.params.id;
  try {
    // get the correct cart, either from the db, session, or an empty cart.
    let user_cart;
    if (req.user) {
      user_cart = await Cart.findOne({ user: req.user._id });
    }
    let cart;
    if (
      (req.user && !user_cart && req.session.cart) ||
      (!req.user && req.session.cart)
    ) {
      cart = await new Cart(req.session.cart);
    } else if (!req.user || !user_cart) {
      cart = new Cart({});
    } else {
      cart = user_cart;
    }

    // add the product to the cart
    const product = await Product.findById(productId);
    const itemIndex = cart.items.findIndex((p) => p.productId == productId);
    if (itemIndex > -1) {
      // if product exists in the cart, update the quantity
      cart.items[itemIndex].qty++;
      cart.items[itemIndex].price = cart.items[itemIndex].qty * product.price;
      cart.totalQty++;
      cart.totalCost += product.price;
    } else {
      // if product does not exists in cart, find it in the db to retrieve its price and add new item
      cart.items.push({
        productId: productId,
        qty: 1,
        price: product.price,
        title: product.title,
        productCode: product.productCode,
      });
      cart.totalQty++;
      cart.totalCost += product.price;
    }

    // if the user is logged in, store the user's id and save cart to the db
    if (req.user) {
      cart.user = req.user._id;
      await cart.save();
    }
    req.session.cart = cart;
    req.flash("success", "Item added to the shopping cart");
    res.redirect(req.headers.referer);
  } catch (err) {
    console.log(err.message);
    res.redirect("/");
  }
});

// POST: handle checkout logic and payment using Stripe
router.post("/checkout", middleware.isLoggedIn, async (req, res) => {
  if (!req.session.cart) {
    req.flash("error", "Your shopping cart is empty.");
    return res.redirect("/shopping-cart");
  }

  let cart;
  try {
    cart = await Cart.findById(req.session.cart._id);
    if (!cart) {
      throw new Error("Cart not found");
    }
  } catch (error) {
    console.error(error.message);
    req.flash("error", "An error occurred while retrieving your cart. Please try again later.");
    return res.redirect("/shopping-cart");
  }

  try {
    const charge = await stripe.paymentIntents.create({
      amount: cart.totalCost * 100,
      currency: "usd",
      payment_method_types: ['card'],
    });

    const order = new Order({
      user: req.user,
      cart: {
        totalQty: cart.totalQty,
        totalCost: cart.totalCost,
        items: cart.items,
      },
      address: req.body.address,
      paymentId: charge.id,
    });

    await order.save();
    await Cart.findByIdAndDelete(cart._id);
    req.flash("success", "Successfully purchased");
    req.session.cart = null;
    return res.redirect("/user/profile");
  } catch (error) {
    console.error(error.message);
    req.flash("error", error.message);
    return res.redirect("/checkout");
  }
});

module.exports = router;
