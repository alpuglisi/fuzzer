# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics". Missing idiomatic counterpart for vulnerable-2.py's
# CWE-362/CWE-367 TOCTOU race (this cell's own manifest.yaml entry:
# arvinmaroufi/MasaiShop's apply_coupon(), a non-atomic
# read-is_valid()-then-increment on Coupon.usage_count). Per this cell's
# manifest.yaml own note, no license-clean real-world locked counterpart
# was found in the original collection pass, so this is manufactured from
# vulnerable-2.py's own real structure per the plan's methodology, using
# the exact mitigations that manifest note itself names as absent
# (select_for_update() / an F() expression, inside a transaction).
#
# Minimal-pair discipline: same function name, same imports (aside from
# the two additions the fix requires: `transaction` and `F`), same
# business logic (same messages, same discount computation, same
# max_usage deactivation), same overall control flow. The ONLY mechanism
# difference is that the coupon row is locked with select_for_update()
# before is_valid() is read, the whole check-then-act sequence runs
# inside one transaction.atomic() block, and the counter increment uses
# an atomic F('usage_count') + 1 update instead of a plain Python
# `+= 1; .save()` -- closing the race window vulnerable-2.py leaves open.

from django.contrib import messages
from django.db import transaction
from django.db.models import F
from django.shortcuts import redirect

from .models import Cart, Coupon


def apply_coupon(request):
    if request.method == 'POST':
        coupon_code = request.POST.get('coupon_code')
        try:
            cart = Cart.objects.get(user=request.user)
            if not cart.items.exists():
                messages.error(request, 'سبد خرید شما خالی است')  # cart is empty
                return redirect('cart:cart')

            with transaction.atomic():
                # --- CHECK + ACT, now inside one transaction with the
                # coupon row locked: select_for_update() blocks any other
                # concurrent request from reading/incrementing the same
                # coupon row until this transaction commits, so two
                # concurrent requests can no longer both pass is_valid()
                # before either commits its increment. ---
                coupon = Coupon.objects.select_for_update().get(code=coupon_code)
                if not coupon.is_valid():
                    messages.error(request, 'کد تخفیف معتبر نیست یا منقضی شده است')
                    return redirect('cart:cart')

                if cart.coupon:
                    messages.warning(request, 'یک کد تخفیف قبلاً اعمال شده است')
                    return redirect('cart:cart')

                total_price = sum(item.total_price for item in cart.items.all())

                if coupon.discount_type == 'percentage':
                    discount = int((total_price * coupon.discount_value) / 100)
                else:
                    discount = coupon.discount_value

                discount = min(discount, total_price)

                cart.coupon = coupon
                cart.coupon_discount = discount
                cart.save()

                # --- ACT: an atomic F() update instead of a Python-side
                # read-modify-write -- the increment happens at the
                # database level in a single UPDATE statement, with no
                # window for a concurrent request to read a stale value. ---
                coupon.usage_count = F('usage_count') + 1
                coupon.save()
                coupon.refresh_from_db()

                if coupon.max_usage and coupon.usage_count >= coupon.max_usage:
                    coupon.is_active = False
                    coupon.save()

            messages.success(
                request,
                f'کد تخفیف {coupon.code} با موفقیت اعمال شد ({discount:,} تومان تخفیف)'
            )
        except Coupon.DoesNotExist:
            messages.error(request, 'کد تخفیف وارد شده معتبر نیست')
        return redirect('cart:cart')
    return redirect('cart:cart')
