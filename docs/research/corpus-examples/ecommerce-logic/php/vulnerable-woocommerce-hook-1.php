<?php
// Manufactured vulnerable variant, derived from
// idiomatic-woocommerce-hook-1.php (WooCommerce core, GPL-3.0-only).
// Illustrates a common real-world WooCommerce extension anti-pattern: a
// plugin/theme callback hooked on the real 'woocommerce_before_calculate_totals'
// action (the same extension point WC_Cart::calculate_totals() fires, shown
// in the idiomatic side) that trusts a client-supplied price instead of
// re-deriving it from the product's own canonical price server-side.
add_action( 'woocommerce_before_calculate_totals', 'apply_client_supplied_price' );

function apply_client_supplied_price( $cart ) {
	if ( is_admin() && ! defined( 'DOING_AJAX' ) ) {
		return;
	}

	foreach ( $cart->get_cart() as $cart_item ) {
		if ( isset( $_POST['custom_price'] ) ) {
			// No re-validation against $cart_item['data']->get_price():
			// whatever price the client posted is trusted outright.
			$cart_item['data']->set_price( floatval( wp_unslash( $_POST['custom_price'] ) ) );
		}
	}
}
