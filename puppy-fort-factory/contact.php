<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Contact';

/*
 * SECURE PAGE.
 * The submitted message is echoed back, but through e(), so the reflection is
 * safe (no XSS). Nothing is written to the database.
 */
$name = $message = '';
$sent = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name    = trim($_POST['name'] ?? '');
    $message = trim($_POST['message'] ?? '');
    $sent    = ($name !== '' && $message !== '');
}

require __DIR__ . '/includes/header.php';
?>
<h1>Contact the fort crew</h1>

<?php if ($sent): ?>
  <p class="notice ok">Thanks <?= e($name) ?>, we got your message:</p>
  <blockquote class="bio"><?= e($message) ?></blockquote>
<?php endif; ?>

<form class="stack" method="post" action="contact.php">
  <label>Your name <input type="text" name="name" value="<?= e($name) ?>"></label>
  <label>Message <textarea name="message"><?= e($message) ?></textarea></label>
  <p><button class="btn" type="submit">Send</button></p>
</form>

<?php require __DIR__ . '/includes/footer.php'; ?>
