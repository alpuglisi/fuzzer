const router = require('express').Router()
const {Order, Art, User, OrderProduct } = require('../db/models');

const stripe = require("stripe")("REDACTED_API_KEY")

module.exports = router

router.post("/charge", async (req, res) => {
  try {
    let {status} = await stripe.charges.create({
      amount: req.body.price,
      currency: "usd",
      description: req.body.order,
      source: req.body.body
    });
    res.json(status);
  } catch (err) {
    console.error(err)
    res.status(500).end();
  }
});

router.post('/', async (req, res, next) => {
  try {
    let order = await Order.create({
      status: 'processing'
    })

    if(req.body.userId) {
      order.status = 'created';
      const userId = req.body.userId;
      const user = await User.findById(userId);
      await user.addOrder(order);
    }

    if(req.body.orderInfo) {
      await order.update(req.body.orderInfo)
    }

    await order.save();

    if(req.body.productIds) {
      const productIds = req.body.productIds;
      let countedProducts = await OrderProduct.findQuantity(productIds);

      let orderArt = await Promise.all(Object.keys(countedProducts).map(productId => Art.findById(productId)));
      await Promise.all(orderArt.map(art => order.addArt(art)));
      await OrderProduct.setQuantity(countedProducts, order.id);

    }
    order = await Order.findOne({
      where: {
        id: order.id
      }, include: [{model: Art, OrderProduct, User }]
    })

    res.json(order)
  } catch (err) {
    next(err)
  }
})

router.get('/', async (req, res, next) => {
  try {
    const orders = await Order.findAll({include: [{model: Art}]});
    res.send(orders)
  } catch (err) {
    next(err)
  }
})

router.get('/:orderId', async (req, res, next) => {
  try {
    const order = await Order.findOne({
      where: {
        id: req.params.orderId
      }, include: [{model: OrderProduct, Art}]
    })
    res.send(order)
  } catch (err) {
    next(err)
  }
})

router.put('/:orderId/:productId', async(req, res, next) => {
  try{
    if(req.body.quantity === '0') {
      await OrderProduct.destroy({
        where: {
          orderId: req.params.orderId,
          artId: req.params.productId
      }})
    } else {
      await OrderProduct.update({
        quantity: req.body.quantity},
          {where: {
          orderId: req.params.orderId,
          artId: req.params.productId
          }}
      )
    }
    const order = await Order.findOne({
      where: {
        id: req.params.orderId
      }, include: [{model: Art, OrderProduct }]
    })
    res.status(202).send(order)
  } catch(err) {
    next(err)
  }
})

router.put('/:orderId', async (req, res, next) => {
  try {
    const order = await Order.findOne({
      where: {
        id: req.params.orderId
      }, include: [{model: Art, OrderProduct }]
    })
    order.status = req.body.status;

    if(req.body.orderInfo) {
      await order.update(req.body.orderInfo)
    }

    await order.save()
    if(req.body.productIds) {
      const productIds = req.body.productIds;
      let countedProducts = await OrderProduct.findQuantity(productIds);
      let orderArt = await Promise.all(Object.keys(countedProducts).map(productId =>
        Art.findById(productId)));
      await Promise.all(orderArt.map(art => order.addArt(art)));
      await OrderProduct.setQuantity(countedProducts, order.id);
    }
    res.send(order)
  } catch (err) {
    next(err)
  }
})
