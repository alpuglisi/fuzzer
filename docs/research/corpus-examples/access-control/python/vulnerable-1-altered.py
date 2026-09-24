# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". Missing vulnerable counterpart for idiomatic-1.py's
# CWE-639/CWE-862 ownership-check idiom (this cell's own manifest.yaml
# entry for idiomatic-1.py: timluh98/FS-Webapp's confirm_payment() /
# confirm_shipping() / confirm_completion() routes). Minimal-pair
# discipline: identical routes, identical imports, identical business
# logic (same status-transition guards), differing ONLY in the removed
# ownership check -- each route trusts `order_id` from the URL and
# performs the state transition for ANY caller, not just the order's
# owner/supplier.

from flask import redirect, url_for, flash
from flask_login import login_required, current_user

from db import db
from models import Order

@app.route('/confirm_payment/<int:order_id>', methods=['POST'])
@login_required
def confirm_payment(order_id):
    order = Order.query.get_or_404(order_id)
    # VULNERABLE: no `order.user_id != current_user.id` check (contrast:
    # idiomatic-1.py's confirm_payment()) -- any authenticated user can
    # confirm payment on ANY order by guessing/incrementing order_id.
    if order.payment_status == 'pending':
        order.payment_status = 'paid'
        db.session.commit()
        flash('Payment confirmed. Supplier has been notified to ship your order.', 'success')
    return redirect(url_for('my_orders'))

@app.route('/confirm_shipping/<int:order_id>', methods=['POST'])
@login_required
def confirm_shipping(order_id):
    order = Order.query.get_or_404(order_id)
    # VULNERABLE: no `purchase.part.supplier_id == current_user.id` check
    # (contrast: idiomatic-1.py's confirm_shipping()) -- any authenticated
    # user, not just a supplier on this order, can mark it shipped.
    if order.shipping_status == 'pending' and order.payment_status == 'paid':
        order.update_shipping_status('shipped')
        db.session.commit()
        flash('Shipping confirmed. Customer has been notified.', 'success')
    return redirect(url_for('my_orders'))

@app.route('/confirm_completion/<int:order_id>', methods=['POST'])
@login_required
def confirm_completion(order_id):
    order = Order.query.get_or_404(order_id)
    # VULNERABLE: no `order.user_id != current_user.id` check (contrast:
    # idiomatic-1.py's confirm_completion()) -- any authenticated user can
    # mark ANY order completed.
    if order.completion_status == 'pending' and order.shipping_status == 'shipped':
        order.completion_status = 'completed'
        db.session.commit()
        flash('Order completion confirmed. Thank you for your purchase!', 'success')
    return redirect(url_for('my_orders'))
