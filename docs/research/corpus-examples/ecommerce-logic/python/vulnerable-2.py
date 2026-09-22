# Excerpt from cart/views.py -- only apply_coupon() (the relevant
# function). See manifest.yaml for the full source file path and commit.
# Comments in Persian in the original translated inline below are left as
# short English notes; the messages.* string literals (user-facing Persian
# text) are kept verbatim as in the source.

from django.contrib import messages
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

            coupon = Coupon.objects.get(code=coupon_code)
            # --- CHECK: is_valid() reads is_active / usage_count / max_usage
            # / expiry, but the row is not locked (no select_for_update()) and
            # there is no surrounding transaction. ---
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

            # --- ACT: plain read-modify-write on a Python-side integer,
            # then .save(). Two concurrent requests for the same coupon can
            # both pass the is_valid() check above before either commits
            # this increment, so usage_count can end up exceeding
            # max_usage -- the single-use / limited-use cap is bypassed. A
            # correct version would use coupon.usage_count = F('usage_count')
            # + 1 (or select_for_update()) inside a transaction. ---
            coupon.usage_count += 1
            coupon.save()

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
