<?php
// Excerpt of QloApps, classes/Cart.php (OSL-3.0). Source: repo
// Qloapps/QloApps, commit de6ecd72f0ce73750bea8d653c47efd9e2eb837b.
// License note: OSL-3.0 (copyleft) -- kept to the method signature and its
// server-side dependency wiring only, per this corpus's copyleft-handling
// rule; the full ~150-line body (tax/rounding/discount branches) is
// deliberately omitted as not illustrative of the specific contrast this
// entry pairs against.

public function getOrderTotal($with_taxes = true, $type = Cart::BOTH, $products = null, $id_carrier = null, $use_cache = true)
{
    // Dependencies
    $address_factory    = Adapter_ServiceLocator::get('Adapter_AddressFactory');
    $price_calculator    = Adapter_ServiceLocator::get('Adapter_ProductPriceCalculator');
    $configuration        = Adapter_ServiceLocator::get('Core_Business_ConfigurationInterface');

    // ... (room/date/occupancy-driven price recomputation via
    // $price_calculator and HotelRoomTypeFeaturePricing, not shown --
    // the total is derived server-side from cart contents on every call,
    // never taken from a client-supplied total field)
}
