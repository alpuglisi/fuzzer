<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Search';

/*
 * !!! VULNERABLE PAGE - SQL INJECTION + REFLECTED XSS !!!
 *
 * 1. SQL injection: `q` is concatenated into a LIKE clause unescaped.
 *      search.php?q=%' UNION SELECT username, password, email, 1 FROM users -- -
 *      search.php?q=x%' AND (SELECT 1 FROM (SELECT(SLEEP(5)))y) -- -
 *
 * 2. Reflected XSS: `q` is echoed back into the page (and into the input
 *    value attribute) without escaping.
 *      search.php?q=<script>alert(document.cookie)</script>
 *      search.php?q="><script>alert(1)</script>
 */
$q = $_GET['q'] ?? '';
$results = null;
$db_error = null;

if ($q !== '') {
    $sql = "SELECT id, name, price, description FROM products
            WHERE name LIKE '%$q%' OR description LIKE '%$q%'";
    $results = mysqli_query($conn, $sql);
    if (!$results) {
        $db_error = mysqli_error($conn);
    }
}

require __DIR__ . '/includes/header.php';
?>
<h1>Search the fort catalogue</h1>

<form method="get" action="search.php">
  <!-- VULNERABLE: value echoed unescaped -> attribute-based reflected XSS -->
  <input type="text" name="q" value="<?= $q ?>" placeholder="Try 'chew' or 'treat'">
  <button class="btn" type="submit">Search</button>
</form>

<?php if ($q !== ''): ?>
  <!-- VULNERABLE: query echoed unescaped -> reflected XSS -->
  <p>Results for <strong><?= $q ?></strong>:</p>

  <?php if ($db_error): ?>
    <p class="error">Query error: <?= $db_error ?></p>
  <?php endif; ?>

  <div class="grid">
  <?php while ($results && $row = mysqli_fetch_assoc($results)): ?>
    <div class="card">
      <h3><a href="product.php?id=<?= (int)$row['id'] ?>"><?= e($row['name']) ?></a></h3>
      <p class="price">$<?= e(number_format((float)$row['price'], 2)) ?></p>
      <p><?= e($row['description']) ?></p>
    </div>
  <?php endwhile; ?>
  </div>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
