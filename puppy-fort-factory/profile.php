<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_login();
$page_title = 'Profile';

/*
 * !!! VULNERABLE PAGE - STORED XSS !!!
 *
 * The profile is fetched with a prepared statement (no SQL injection), but the
 * `bio` field is rendered WITHOUT escaping. Whatever a user saves in their bio
 * on edit_profile.php executes here.
 *
 * Save this as your bio on edit_profile.php, then load this page:
 *   <script>alert(document.cookie)</script>
 *   <img src=x onerror=alert('stored-xss')>
 */
$user_id = (int)current_user_id();

$stmt = mysqli_prepare(
    $conn,
    "SELECT username, email, full_name, bio, address, created_at FROM users WHERE id = ?"
);
mysqli_stmt_bind_param($stmt, 'i', $user_id);
mysqli_stmt_execute($stmt);
$u = mysqli_stmt_get_result($stmt)->fetch_assoc();

require __DIR__ . '/includes/header.php';
?>
<h1>Your profile</h1>

<?php if (!$u): ?>
  <p>Profile not found.</p>
<?php else: ?>
  <p><strong>Username:</strong> <?= e($u['username']) ?></p>
  <p><strong>Email:</strong> <?= e($u['email']) ?></p>
  <p><strong>Full name:</strong> <?= e($u['full_name']) ?></p>
  <p><strong>Address:</strong> <?= e($u['address']) ?></p>
  <p><strong>Member since:</strong> <?= e($u['created_at']) ?></p>

  <h2>About me</h2>
  <!-- VULNERABLE: bio rendered unescaped -> stored XSS -->
  <div class="bio"><?= $u['bio'] !== null && $u['bio'] !== '' ? $u['bio'] : '<span class="muted">No bio yet.</span>' ?></div>

  <p><a class="btn" href="edit_profile.php">Edit profile</a></p>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
