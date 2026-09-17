<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Register';

/*
 * SECURE PAGE.
 * - Duplicate check and insert both use prepared statements (no SQL injection).
 * - Every value echoed back is escaped with e() (no XSS).
 * (Passwords are stored as MD5 for app-wide consistency; that crypto weakness
 *  is documented separately and is not an SQLi/XSS issue.)
 */
$errors = [];
$done = false;
$username = $email = $full_name = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username  = trim($_POST['username'] ?? '');
    $email     = trim($_POST['email'] ?? '');
    $password  = $_POST['password'] ?? '';
    $full_name = trim($_POST['full_name'] ?? '');

    if ($username === '' || $email === '' || $password === '') {
        $errors[] = 'Username, email and password are all required.';
    }
    if (strlen($password) < 6) {
        $errors[] = 'Password must be at least 6 characters.';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }

    if (!$errors) {
        $stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE username = ?");
        mysqli_stmt_bind_param($stmt, 's', $username);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);
        if (mysqli_stmt_num_rows($stmt) > 0) {
            $errors[] = 'That username is already taken.';
        } else {
            $hash = md5($password);
            $ins = mysqli_prepare(
                $conn,
                "INSERT INTO users (username, email, password, full_name, bio) VALUES (?, ?, ?, ?, '')"
            );
            mysqli_stmt_bind_param($ins, 'ssss', $username, $email, $hash, $full_name);
            mysqli_stmt_execute($ins);
            $done = true;
        }
    }
}

require __DIR__ . '/includes/header.php';
?>
<h1>Create your account</h1>

<?php if ($done): ?>
  <p class="notice ok">Welcome to the pack, <?= e($username) ?>! You can now <a href="login.php">log in</a>.</p>
<?php else: ?>
  <?php foreach ($errors as $err): ?>
    <p class="notice err"><?= e($err) ?></p>
  <?php endforeach; ?>

  <form class="stack" method="post" action="register.php">
    <label>Username <input type="text" name="username" value="<?= e($username) ?>" required></label>
    <label>Email <input type="email" name="email" value="<?= e($email) ?>" required></label>
    <label>Full name <input type="text" name="full_name" value="<?= e($full_name) ?>"></label>
    <label>Password <input type="password" name="password" required></label>
    <p><button class="btn" type="submit">Register</button></p>
  </form>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
