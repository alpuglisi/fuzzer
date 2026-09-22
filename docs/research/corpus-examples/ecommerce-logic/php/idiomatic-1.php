<?php
// Excerpt from application/controllers/cart.php -- only the process()
// method (PayPal Express Checkout submission), which is the relevant
// contrast to vulnerable-1.php: rather than trusting a client-supplied
// price/total at the charge step, it looks each line item's price up
// fresh from Product_model (the DB) and accumulates the order total
// itself before ever building the payment request. See manifest.yaml
// for the full source file path and commit; unrelated methods (index,
// add, update, payment_success) are omitted for size per this corpus's
// copyleft-handling rule (smallest illustrative fragment).

class Cart extends CI_Controller {

    public $paypal_data = '';
    public $tax;
    public $shipping;
    public $total = 0;
    public $grand_total;

    public function process(){
        $this->tax = $this->config->item('tax');
        $this->shipping = $this->config->item('shipping');
        if($_POST) {
            $this->paypal_data = '';
            foreach ($this->input->post('item_name') as $key => $value)
            {
                $item_id = $this->input->post( 'item_code' )[ $key ];
                // Authoritative price lookup: the per-item price used for
                // the charge always comes from the DB record, never from
                // whatever the client posted for this line item.
                $product = $this->Product_model->get_product_details( $item_id );

                $this->paypal_data .= '&L_PAYMENTREQUEST_0_NAME' . $key . '=' . urlencode( $product->title );
                $this->paypal_data .= '&L_PAYMENTREQUEST_0_NUMBER' . $key . '=' . urlencode( $item_id );
                $this->paypal_data .= '&L_PAYMENTREQUEST_0_AMT' . $key . '=' . urlencode( $product->price );
                $this->paypal_data .= '&L_PAYMENTREQUEST_0_QTY' . $key . '=' . urlencode( $this->input->post( 'item_qty' )[ $key ] );

                // Price x quantity, computed server-side from $product->price
                $subtotal    = ( $product->price * $this->input->post( 'item_qty' )[ $key ] );
                $this->total = $this->total + $subtotal;

                $paypal_product[ 'items' ][ ] = array(
                    'itm_name' => $product->title,
                    'itm_price' => $product->price,
                    'itm_code' => $item_id,
                    'itm_qty' => $this->input->post( 'item_qty' )[ $key ]
                );
            }

            $order_data = array(
                'user_id' => $this->session->userdata('user_id'),
                'transaction_id' => 0,
                'address'  => $this->input->post('address'),
                'address2' => $this->input->post('address2'),
                'phone'    => $this->input->post('phone'),
                'city'     => $this->input->post('city'),
                'state'    => $this->input->post('state'));

            if ($order_id = $this->Cart_model->add_order($order_data)){
                $details = $paypal_product['items'];
                foreach($details as $key => $csm)
                {
                    $details[$key]['order_id'] = $order_id;
                }

                if($this->Cart_model->add_order_details($details)){
                    $this->grand_total = $this->total + $this->tax + $this->shipping;

                    $paypal_product['assets'] = array(
                        'tax_total'     => $this->tax,
                        'shipping_cost' => $this->shipping,
                        'grand_total'   => $this->total );
                    $_SESSION['paypal_products'] = $paypal_product;

                    // The amount sent to PayPal is $this->total /
                    // $this->grand_total, both derived above from
                    // $product->price -- never from a client-posted total.
                    $padata = '&METHOD=SetExpressCheckout'.
                        '&RETURNURL='.urlencode($this->config->item('paypal_return_url')).
                        '&CANCELURL='.urlencode($this->config->item('paypal_cancel_url')).
                        '&PAYMENTREQUEST_0_PAYMENTACTION='.urlencode("SALE").
                        $this->paypal_data.
                        '&NOSHIPPING=0'.
                        '&PAYMENTREQUEST_0_ITEMAMT='.urlencode($this->total).
                        '&PAYMENTREQUEST_0_TAXAMT='.urlencode($this->tax).
                        '&PAYMENTREQUEST_0_SHIPPINGAMP='.urlencode($this->shipping).
                        '&PAYMENTREQUEST_0_AMT='.urlencode($this->grand_total).
                        '&PAYMENTREQUEST_0_CURRENCYCODE='.urlencode($this->config->item('paypal_currency_code')).
                        '&LOCALECODE=GB'.
                        '&CARTBORDERCOLOR=FFFFFF'.
                        '&ALLOWNOTE=1';

                    $httpParsedResponseAr = $this->paypal->PPHttpPost(
                        'SetExpressCheckout', $padata,
                        $this->config->item('paypal_api_username'),
                        $this->config->item('paypal_api_password'),
                        $this->config->item('paypal_api_signature'),
                        $this->config->item('paypal_api_endpoint')
                    );

                    if("SUCCESS" == strtoupper($httpParsedResponseAr['ACK']) || "SUCCESSWITHWARNING" == strtoupper($httpParsedResponseAr["ACK"])){
                        $paypal_url = 'https://www.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token='.$httpParsedResponseAr["TOKEN"];
                        header('Location: '.$paypal_url);
                    } else {
                        print_r($httpParsedResponseAr);
                        die(urldecode($httpParsedResponseAr["L_LONGMESSAGE0"]));
                    }
                } else {
                    die('cannot save your order. Please contact system administrator');
                }
            }
        }
    }
}
