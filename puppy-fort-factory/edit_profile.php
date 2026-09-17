<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_login();
$page_title = 'Edit Profile';

/*
 * SECURE against SQL INJECTION (prepared statement update), and the form fields
 * below are pre-filled with e() so the form itself is not reflected-XSS.
 *
 * However, the `bio` value is stored verbatim and later rendered unescaped by
 * profile.php. This page is therefore the INPUT POINT of the stored XSS whose
 * SINK is profile.php. That is intentional and documented in VULNERABILITIES.md.
 */
$user_id = (int)current_user_id();
$saved = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = $_POST['full_name'] ?? '';
    $email     = $_POST['email'] ?? '';
    $address   = $_POST['address'] ?? '';
    $bio       = $_POST['bio'] ?? '';

    $stmt = mysqli_prepare(
        $conn,
        "UPDATE users SET full_name = ?, email = ?, address = ?, bio = ? WHERE id = ?"
    );
    mysqli_stmt_bind_param($stmt, 'ssssi', $full_name, $email, $address, $bio, $user_id);
    mysqli_stmt_execute($stmt);
    $saved = true;
}

$stmt = mysqli_prepare($conn, "SELECT full_name, email, address, bio FROM users WHERE id = ?");
mysqli_stmt_bind_param($stmt, 'i', $user_id);
mysqli_stmt_execute($stmt);
$u = mysqli_stmt_get_result($stmt)->fetch_assoc();

require __DIR__ . '/includes/header.php';
?>
<h1>Edit profile</h1>

<?php if ($saved): ?>
  <p class="notice ok">Profile saved. <a href="profile.php">View your profile.</a></p>
<?php endif; ?>

<form class="stack" method="post" action="edit_profile.php">
  <label>Full name <input type="text" name="full_name" value="<?= e($u['full_name']) ?>"></label>
  <label>Email <input type="email" name="email" value="<?= e($u['email']) ?>"></label>
  <label>Address <input type="text" name="address" value="<?= e($u['address']) ?>"></label>
  <label>Bio <textarea name="bio"><?= e($u['bio']) ?></textarea></label>
  <p><button class="btn" type="submit">Save changes</button></p>
</form>

<?php require __DIR__ . '/includes/footer.php'; ?>
