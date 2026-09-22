<?php
// Manufactured vulnerable variant, derived from
// idiomatic-qloapps-booking-1.php (QloApps, OSL-3.0). Illustrates a common
// real-world anti-pattern in booking-engine payment-module integrations: a
// custom payment callback that trusts a client-posted booking total instead
// of calling getOrderTotal() (the real server-side recomputation entry
// point shown in the idiomatic side) to re-derive it from the cart's room/
// date/occupancy data (CWE-840: Business Logic Errors / price tampering).
// License note: derived from OSL-3.0 code -- see the idiomatic entry's
// license note; the same caution applies here.

class CustomPaymentModuleFrontController extends FrontController
{
    public function postProcess()
    {
        $cart = Context::getContext()->cart;

        // Trusts $_POST['total_price'] outright instead of calling
        // $cart->getOrderTotal(true, Cart::BOTH) -- the same object the
        // idiomatic side's method lives on -- so a guest who edits the
        // hidden form field before submit is charged whatever amount they
        // posted, not what the booked rooms/dates actually cost.
        $totalToCharge = (float) Tools::getValue('total_price');

        $this->module->validateOrder(
            $cart->id,
            Configuration::get('PS_OS_PAYMENT'),
            $totalToCharge,
            $this->module->displayName,
            null,
            array(),
            null,
            false,
            $cart->secure_key
        );
    }
}
