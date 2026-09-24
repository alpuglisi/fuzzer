# idiomatic-3-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". Referral-credit redemption at checkout -- a distinct
# sub-scenario from this file's price-tampering pair (vulnerable-1.py/
# idiomatic-1.py) and from the coupon-race pair (vulnerable-2.py/
# idiomatic-2-altered.py). The credit actually applied is always
# recomputed server-side from the ReferralCredit record's own stored
# remaining_cents balance, clamped to the order's own computed subtotal --
# never taken from a client-supplied amount.
from django.db import transaction
from django.http import JsonResponse

from .models import Order, ReferralCredit


def apply_referral_credit(request, order_id):
    order = Order.objects.select_related("customer").get(pk=order_id, customer=request.user)
    subtotal_cents = int(sum(item.unit_price_cents * item.quantity for item in order.items.all()))

    credit = ReferralCredit.objects.filter(customer=request.user, active=True).first()
    if credit is None:
        return JsonResponse({"applied_cents": 0, "total_cents": subtotal_cents})

    with transaction.atomic():
        applied_cents = min(credit.remaining_cents, subtotal_cents)
        credit.remaining_cents -= applied_cents
        credit.active = credit.remaining_cents > 0
        credit.save(update_fields=["remaining_cents", "active"])

    return JsonResponse({
        "applied_cents": applied_cents,
        "total_cents": subtotal_cents - applied_cents,
    })
