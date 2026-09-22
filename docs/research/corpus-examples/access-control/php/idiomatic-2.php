<?php
/**
 * Syre Bijouteries - Cancel Order
 * Handles order cancellation
 */

require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/functions.php';

requireLogin();

$order_id = (int)($_GET['id'] ?? 0);

if ($order_id <= 0) {
    setMessage('error', 'Invalid order');
    redirect('orders.php');
}

// Get order and verify ownership
$order_sql = "SELECT * FROM orders WHERE id = $order_id AND user_id = " . $_SESSION['user_id'];
$order_result = $conn->query($order_sql);

if (!$order_result || $order_result->num_rows === 0) {
    setMessage('error', 'Order not found');
    redirect('orders.php');
}

$order = $order_result->fetch_assoc();

// Can only cancel pending orders
if ($order['order_status'] !== 'pending') {
    setMessage('error', 'Only pending orders can be cancelled');
    redirect('order-detail.php?id=' . $order_id);
}

// Update order status to cancelled
$update_sql = "UPDATE orders SET order_status = 'cancelled', updated_at = NOW() WHERE id = $order_id";

if ($conn->query($update_sql)) {
    setMessage('success', 'Order #' . str_pad($order_id, 6, '0', STR_PAD_LEFT) . ' has been cancelled successfully');
} else {
    setMessage('error', 'Failed to cancel order. Please try again.');
}

redirect('order-detail.php?id=' . $order_id);

