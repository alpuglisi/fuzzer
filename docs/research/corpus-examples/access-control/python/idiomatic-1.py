# Excerpt from app.py (order-confirmation routes only; imports trimmed to
# what these routes need). Full file: 650 lines, MIT licensed.
# Source: timluh98/FS-Webapp @ a01089943d6a6850b97ab7ddd7f6eb51304850ac

from flask import redirect, url_for, flash
from flask_login import login_required, current_user

from db import db
from models import Order

@app.route('/confirm_payment/<int:order_id>', methods=['POST'])
@login_required
def confirm_payment(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('You can only confirm payment for your own orders.', 'danger')
        return redirect(url_for('my_orders'))

    if order.payment_status == 'pending':
        order.payment_status = 'paid'
        db.session.commit()
        flash('Payment confirmed. Supplier has been notified to ship your order.', 'success')
    return redirect(url_for('my_orders'))

@app.route('/confirm_shipping/<int:order_id>', methods=['POST'])
@login_required
def confirm_shipping(order_id):
    order = Order.query.get_or_404(order_id)
    is_supplier = any(
        purchase.part.supplier_id == current_user.id
        for purchase in order.purchases
    )

    if not is_supplier:
        flash('You can only confirm shipping for orders containing your parts.', 'danger')
        return redirect(url_for('my_orders'))

    if order.shipping_status == 'pending' and order.payment_status == 'paid':
        order.update_shipping_status('shipped')
        db.session.commit()
        flash('Shipping confirmed. Customer has been notified.', 'success')
    return redirect(url_for('my_orders'))

@app.route('/confirm_completion/<int:order_id>', methods=['POST'])
@login_required
def confirm_completion(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('You can only confirm completion for your own orders.', 'danger')
        return redirect(url_for('my_orders'))

    if order.completion_status == 'pending' and order.shipping_status == 'shipped':
        order.completion_status = 'completed'
        db.session.commit()
        flash('Order completion confirmed. Thank you for your purchase!', 'success')
    return redirect(url_for('my_orders'))
