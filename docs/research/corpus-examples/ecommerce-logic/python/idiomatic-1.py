# Excerpt from orders/views.py -- process_order() and process_payment()
# (the two functions relevant to this corpus entry: computing the order
# total server-side, then charging exactly that computed total). See
# manifest.yaml for the full source file path and commit. Referenced
# names (Order, OrderItem, DEFAULT_SHIPPING_COST, TAX_RATE, logger,
# send_order_confirmation, ...) are defined elsewhere in the source file.

from decimal import Decimal

from django.db import transaction
from django.shortcuts import redirect
from django.utils import timezone
from django.contrib import messages

import stripe


def process_order(request, cart, form):
    """Process and create a new order (legacy fallback)."""
    with transaction.atomic():
        # Create order
        order = form.save(commit=False)
        order.user = request.user
        order.subtotal = cart.subtotal
        order.shipping_cost = DEFAULT_SHIPPING_COST
        order.tax = (cart.subtotal * TAX_RATE).quantize(Decimal('0.01'))
        # Total is derived entirely from cart.subtotal (itself built from
        # each cart item's product.price below), never from a client-
        # supplied total/amount field.
        order.total = (order.subtotal + order.shipping_cost + order.tax).quantize(Decimal('0.01'))
        order.save()

        # Create order items -- price is copied from cart_item.product.price
        # (the DB record), not from anything posted by the client.
        for cart_item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )

        # Process payment
        if not process_payment(order):
            raise Exception("Payment processing failed")

        # Update order status
        order.payment_status = True
        order.payment_date = timezone.now()
        order.save()

        # Clear cart
        cart.clear()

        # Send confirmation
        send_order_confirmation(order)

        messages.success(request, "Your order has been placed successfully!")
        logger.info(f"Order {order.order_number} created successfully")
        return redirect('orders:order_confirmation', order_number=order.order_number)


def process_payment(order):
    """Process payment through Stripe."""
    try:
        # The charge amount comes from order.total, which was computed
        # entirely server-side above -- the charge step never reads a
        # price/amount out of the request.
        intent = stripe.PaymentIntent.create(
            amount=int(order.total * 100),
            currency='usd',
            metadata={
                'order_id': order.id,
                'user_id': order.user.id
            },
            description=f"Order #{order.order_number}"
        )
        logger.info(f"Payment processed for order {order.order_number}")
        return True
    except stripe.error.StripeError as e:
        logger.error(f"Payment failed for order {order.order_number}: {str(e)}")
        return False
