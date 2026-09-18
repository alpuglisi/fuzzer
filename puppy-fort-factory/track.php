<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Track Order';

/*
 * SECURE PAGE.
 * The order id is coerced to an integer and only ever echoed as an integer, and
 * the status is canned demo data (no database query). No injection surface.
 */
$order_id = isset($_GET['order_id']) ? (int)$_GET['order_id'] : 0;
$statuses = ['Order received', 'In the workshop', 'Out for delivery', 'Delivered'];

require __DIR__ . '/includes/header.php';
?>
<h1>Track your order</h1>

<form method="get" action="track.php">
  <label>Order number
    <input type="number" name="order_id" value="<?= $order_id ?: '' ?>" min="1">
  </label>
  <button class="btn" type="submit">Track</button>
</form>

<?php if ($order_id > 0): ?>
  <?php $state = $statuses[$order_id % count($statuses)]; ?>
  <p class="notice ok">Order #<?= $order_id ?>: <strong><?= e($state) ?></strong> 🐾</p>
<?php endif; ?>
<?php require __DIR__ . '/includes/footer.php'; ?>
