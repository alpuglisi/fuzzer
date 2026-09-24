# vulnerable-3-altered.py
# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" -- derived from idiomatic-3-altered.py's own real structure,
# altered ONLY in how the applied credit amount is decided: the client's
# own posted `credit_cents` field is trusted outright instead of
# recomputing it from the ReferralCredit record's stored balance.
from django.db import transaction
from django.http import JsonResponse

from .models import Order, ReferralCredit


def apply_referral_credit(request, order_id):
    order = Order.objects.select_related("customer").get(pk=order_id, customer=request.user)
    subtotal_cents = int(sum(item.unit_price_cents * item.quantity for item in order.items.all()))

    credit = ReferralCredit.objects.filter(customer=request.user, active=True).first()
    if credit is None:
        return JsonResponse({"applied_cents": 0, "total_cents": subtotal_cents})

    # Business-logic flaw: the amount applied is whatever the client
    # claims in credit_cents, not the record's own stored remaining_cents
    # and not clamped to the order's own computed subtotal. A negative
    # credit_cents even flips the subtraction below into an increase of
    # the credit's own remaining balance.
    applied_cents = int(request.POST.get("credit_cents", 0))

    with transaction.atomic():
        credit.remaining_cents -= applied_cents
        credit.active = credit.remaining_cents > 0
        credit.save(update_fields=["remaining_cents", "active"])

    return JsonResponse({
        "applied_cents": applied_cents,
        "total_cents": subtotal_cents - applied_cents,
    })
