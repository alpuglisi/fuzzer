<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Shop';

/*
 * SECURE PAGE.
 * The optional category filter is applied with a prepared statement, and all
 * output is escaped with e(). No SQL injection or XSS here.
 */
$category = $_GET['category'] ?? '';

if ($category !== '') {
    $stmt = mysqli_prepare(
        $conn,
        "SELECT id, name, price, description, category FROM products WHERE category = ? ORDER BY name"
    );
    mysqli_stmt_bind_param($stmt, 's', $category);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
} else {
    $result = mysqli_query(
        $conn,
        "SELECT id, name, price, description, category FROM products ORDER BY name"
    );
}

$cats = mysqli_query($conn, "SELECT DISTINCT category FROM products ORDER BY category");

require __DIR__ . '/includes/header.php';
?>
<h1>Shop all forts</h1>

<p class="filters">
  <a href="products.php">All</a>
<?php while ($c = mysqli_fetch_assoc($cats)): ?>
  &middot; <a href="products.php?category=<?= urlencode($c['category']) ?>"><?= e(ucfirst($c['category'])) ?></a>
<?php endwhile; ?>
</p>

<div class="grid">
<?php while ($p = mysqli_fetch_assoc($result)): ?>
  <div class="card">
    <h3><a href="product.php?id=<?= (int)$p['id'] ?>"><?= e($p['name']) ?></a></h3>
    <p class="price">$<?= e(number_format((float)$p['price'], 2)) ?></p>
    <p><?= e($p['description']) ?></p>
    <a class="btn" href="product.php?id=<?= (int)$p['id'] ?>">View</a>
  </div>
<?php endwhile; ?>
</div>

<?php require __DIR__ . '/includes/footer.php'; ?>
