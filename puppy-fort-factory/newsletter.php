<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Newsletter';

/*
 * SECURE PAGE.
 * The submitted email is only echoed back through e() (no XSS) and is not
 * written to the database, so there is no injection surface.
 */
$email = '';
$subscribed = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $subscribed = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

require __DIR__ . '/includes/header.php';
?>
<h1>Fort Factory newsletter</h1>
<p>Monthly deals, new forts, and at least one photo of a puppy asleep in a moat.</p>

<?php if ($subscribed): ?>
  <p class="notice ok">Thanks! We'll send fort news to <?= e($email) ?>.</p>
<?php elseif ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
  <p class="notice err">Please enter a valid email address.</p>
<?php endif; ?>

<form class="stack" method="post" action="newsletter.php">
  <label>Email <input type="email" name="email" value="<?= e($email) ?>" required></label>
  <p><button class="btn" type="submit">Subscribe</button></p>
</form>
<?php require __DIR__ . '/includes/footer.php'; ?>
