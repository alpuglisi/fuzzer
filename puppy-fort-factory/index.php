<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Home';

// SECURE: no user input in this query.
$featured = mysqli_query($conn, "SELECT id, name, price, description FROM products ORDER BY id LIMIT 4");

require __DIR__ . '/includes/header.php';
?>
<section class="hero">
  <h1>Forts fit for the goodest pups 🐶</h1>
  <p>Hand-built puppy forts, chew-proof walls, squeaky drawbridges and edible battlements.</p>
  <a class="btn" href="products.php">Shop the fort collection</a>
</section>

<h2>Featured forts</h2>
<div class="grid">
<?php while ($p = mysqli_fetch_assoc($featured)): ?>
  <div class="card">
    <h3><a href="product.php?id=<?= (int)$p['id'] ?>"><?= e($p['name']) ?></a></h3>
    <p class="price">$<?= e(number_format((float)$p['price'], 2)) ?></p>
    <p><?= e($p['description']) ?></p>
    <a class="btn" href="product.php?id=<?= (int)$p['id'] ?>">View</a>
  </div>
<?php endwhile; ?>
</div>

<?php require __DIR__ . '/includes/footer.php'; ?>
