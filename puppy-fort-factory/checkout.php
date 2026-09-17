<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_login();
$page_title = 'Checkout';

/*
 * SECURE PAGE.
 * Reads the cart with a prepared statement and, on confirmation, clears it with
 * another prepared statement. No payment is actually processed - this is a lab.
 */
$user_id = (int)current_user_id();
$placed = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['place_order'])) {
    $stmt = mysqli_prepare($conn, "DELETE FROM cart_items WHERE user_id = ?");
    mysqli_stmt_bind_param($stmt, 'i', $user_id);
    mysqli_stmt_execute($stmt);
    $placed = true;
}

$stmt = mysqli_prepare(
    $conn,
    "SELECT p.name, p.price, ci.quantity
     FROM cart_items ci JOIN products p ON p.id = ci.product_id
     WHERE ci.user_id = ? ORDER BY ci.added_at"
);
mysqli_stmt_bind_param($stmt, 'i', $user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$items = [];
$total = 0.0;
while ($row = mysqli_fetch_assoc($result)) {
    $total += (float)$row['price'] * (int)$row['quantity'];
    $items[] = $row;
}

require __DIR__ . '/includes/header.php';
?>
<h1>Checkout</h1>

<?php if ($placed): ?>
  <p class="notice ok">Order placed! Your forts are on the way. 🐾</p>
  <p><a class="btn" href="products.php">Keep shopping</a></p>
<?php elseif (!$items): ?>
  <p>Your cart is empty. <a href="products.php">Add some forts first.</a></p>
<?php else: ?>
  <table class="cart">
    <thead><tr><th>Item</th><th>Price</th><th>Qty</th></tr></thead>
    <tbody>
    <?php foreach ($items as $it): ?>
      <tr>
        <td><?= e($it['name']) ?></td>
        <td>$<?= e(number_format((float)$it['price'], 2)) ?></td>
        <td><?= (int)$it['quantity'] ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
    <tfoot><tr><td colspan="2">Total</td><td>$<?= e(number_format($total, 2)) ?></td></tr></tfoot>
  </table>
  <form method="post" action="checkout.php">
    <button class="btn" type="submit" name="place_order" value="1">Place order</button>
  </form>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
