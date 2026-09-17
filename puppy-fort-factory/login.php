<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Login';

/*
 * !!! VULNERABLE PAGE - SQL INJECTION / AUTHENTICATION BYPASS !!!
 *
 * The `username` value is concatenated raw into the query. The password is
 * MD5-hashed in the query, so injection in the username field is the entry
 * point.
 *
 * Auth bypass (log in as the first user without a password):
 *   username:  admin' -- -
 *   username:  ' OR '1'='1' -- -
 * Data extraction / time-based injection also work on the username field.
 */
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $sql = "SELECT id, username FROM users
            WHERE username = '$username' AND password = '" . md5($password) . "'";
    $result = mysqli_query($conn, $sql);

    if ($result && $row = mysqli_fetch_assoc($result)) {
        $_SESSION['user_id']  = (int)$row['id'];
        $_SESSION['username'] = $row['username'];
        header('Location: profile.php');
        exit;
    }
    $error = 'Invalid username or password.';
}

require __DIR__ . '/includes/header.php';
?>
<h1>Log in</h1>

<?php if ($error): ?>
  <p class="notice err"><?= e($error) ?></p>
<?php endif; ?>

<form class="stack" method="post" action="login.php">
  <label>Username <input type="text" name="username" required></label>
  <label>Password <input type="password" name="password"></label>
  <p><button class="btn" type="submit">Log in</button></p>
</form>
<p>No account yet? <a href="register.php">Register here</a>.</p>

<?php require __DIR__ . '/includes/footer.php'; ?>
