// Excerpt from controllers/paymentController.js -- only the
// createPaymentIntent handler (the code relevant to this corpus entry).
// See manifest.yaml for the full source file path and commit.

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const Cart = require('../models/Cart')
const Product = require('../models/Product')
const Order = require('../models/Order')
const UserAddress = require('../models/UserAddress')

exports.createPaymentIntent = async (req, res) => {
  try {
    const userId = req.user.id
    const cart = await Cart.findOne({ ownerId: userId }).populate({
      path: 'items.productId',
      select: 'price salePrice stockCount title',
    })

    if (!cart || cart.items.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Cart is empty. Add items to your cart before proceeding to payment.',
      })
    }

    let totalAmount = 0

    for (const item of cart.items) {
      if (item.quantity > item.productId.stockCount) {
        return res.status(400).json({
          success: false,
          message: `Insufficient stock for product: ${item.productId.title}`,
        })
      }

      const price = item.productId.salePrice ?? item.productId.price

      if (typeof price !== 'number') {
        return res.status(400).json({
          success: false,
          message: `Invalid price for product: ${item.productId.title}`,
        })
      }

      totalAmount += item.quantity * price
    }

    if (typeof cart.cargoFee !== 'number' || cart.cargoFee < 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid cargo fee. Please check your cart.',
      })
    }

    totalAmount += cart.cargoFee

    if (totalAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid total amount. Please check your cart.',
      })
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(totalAmount * 100),
      currency: 'usd',
      description: 'E-commerce Payment',
      automatic_payment_methods: {
        enabled: true,
      },
      metadata: {
        userId: userId,
        cartId: cart._id.toString(),
      },
    })

    res.status(200).json({
      success: true,
      paymentIntent: {
        id: paymentIntent.id,
        clientSecret: paymentIntent.client_secret,
      },
    })
  } catch (error) {
    console.error('Error creating payment intent:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to create payment intent',
      error: error.message,
    })
  }
}
