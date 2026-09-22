<?php
// Excerpt of WooCommerce core, WC_Cart::calculate_totals() (GPL-3.0-only).
// Source: plugins/woocommerce/includes/class-wc-cart.php,
// repo woocommerce/woocommerce, commit
// c4ed11e2a9102f400f3b975043a2a29ecf4236e5.
public function calculate_totals() {
	$this->reset_totals();

	if ( $this->is_empty() ) {
		$this->session->set_session();
		return;
	}

	do_action( 'woocommerce_before_calculate_totals', $this );

	new WC_Cart_Totals( $this );

	do_action( 'woocommerce_after_calculate_totals', $this );
}
