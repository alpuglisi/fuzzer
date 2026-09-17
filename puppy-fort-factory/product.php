<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Product';

/*
 * !!! VULNERABLE PAGE - SQL INJECTION !!!
 *
 * The `id` GET parameter is concatenated straight into the query with no
 * validation or parameterisation. This is the primary target for the
 * time-based blind SQLi fuzzer.
 *
 * Try:
 *   product.php?id=1
 *   product.php?id=0 UNION SELECT username,password,email,'x','y',1 FROM users
 *   product.php?id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)
 *
 * (Note: mysqli_query runs a single statement, so stacked queries such as
 *  "; WAITFOR ..." do not apply here; SLEEP/boolean/UNION do.)
 */
$id = $_GET['id'] ?? '1';
$sql = "SELECT id, name, description, price, category, stock FROM products WHERE id = $id";
$result = mysqli_query($conn, $sql);

$db_error = null;
if (!$result) {
    // Verbose DB errors are surfaced, which also enables error-based SQLi.
    $db_error = mysqli_error($conn);
}
$product = $result ? mysqli_fetch_assoc($result) : null;

require __DIR__ . '/includes/header.php';
?>
<?php if ($db_error): ?>
  <p class="error">Query error: <?= $db_error ?></p>
<?php endif; ?>

<?php if (!$product): ?>
  <p>Sorry, we couldn't find that fort.</p>
  <p><a href="products.php">Back to the shop</a></p>
<?php else: ?>
  <article class="product-detail">
    <p><a href="products.php">&larr; Back to shop</a></p>
    <h1><?= e($product['name']) ?></h1>
    <p class="price">$<?= e(number_format((float)$product['price'], 2)) ?></p>
    <p class="muted">Category: <?= e($product['category']) ?> &middot; In stock: <?= (int)$product['stock'] ?></p>
    <p><?= e($product['description']) ?></p>

    <form action="add_to_cart.php" method="post">
      <input type="hidden" name="product_id" value="<?= (int)$product['id'] ?>">
      <label>Quantity
        <input type="number" name="quantity" value="1" min="1" style="width:70px">
      </label>
      <button class="btn" type="submit">Add to cart</button>
    </form>
  </article>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
