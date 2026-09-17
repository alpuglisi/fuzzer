<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_login();
$page_title = 'Your Cart';

/*
 * SECURE PAGE.
 * All queries use prepared statements scoped to the current user, all inputs
 * are integer-cast, and all output is escaped with e().
 */
$user_id = (int)current_user_id();

// Remove an item.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove'])) {
    $cart_id = (int)$_POST['remove'];
    $stmt = mysqli_prepare($conn, "DELETE FROM cart_items WHERE id = ? AND user_id = ?");
    mysqli_stmt_bind_param($stmt, 'ii', $cart_id, $user_id);
    mysqli_stmt_execute($stmt);
    header('Location: cart.php');
    exit;
}

$stmt = mysqli_prepare(
    $conn,
    "SELECT ci.id, p.name, p.price, ci.quantity
     FROM cart_items ci
     JOIN products p ON p.id = ci.product_id
     WHERE ci.user_id = ?
     ORDER BY ci.added_at"
);
mysqli_stmt_bind_param($stmt, 'i', $user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$items = [];
$total = 0.0;
while ($row = mysqli_fetch_assoc($result)) {
    $row['line_total'] = (float)$row['price'] * (int)$row['quantity'];
    $total += $row['line_total'];
    $items[] = $row;
}

require __DIR__ . '/includes/header.php';
?>
<h1>Your cart</h1>

<?php if (!$items): ?>
  <p>Your cart is empty. <a href="products.php">Go build a fort.</a></p>
<?php else: ?>
  <table class="cart">
    <thead>
      <tr><th>Item</th><th>Price</th><th>Qty</th><th>Line total</th><th></th></tr>
    </thead>
    <tbody>
    <?php foreach ($items as $it): ?>
      <tr>
        <td><?= e($it['name']) ?></td>
        <td>$<?= e(number_format((float)$it['price'], 2)) ?></td>
        <td><?= (int)$it['quantity'] ?></td>
        <td>$<?= e(number_format($it['line_total'], 2)) ?></td>
        <td>
          <form method="post" action="cart.php" style="margin:0">
            <input type="hidden" name="remove" value="<?= (int)$it['id'] ?>">
            <button class="btn" type="submit">Remove</button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
    <tfoot>
      <tr><td colspan="3">Total</td><td colspan="2">$<?= e(number_format($total, 2)) ?></td></tr>
    </tfoot>
  </table>
  <p><a class="btn" href="checkout.php">Proceed to checkout</a></p>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
