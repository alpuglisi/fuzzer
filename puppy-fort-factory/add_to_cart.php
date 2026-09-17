<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_login();

/*
 * SECURE PAGE.
 * Inputs are cast to integers and the upsert uses a prepared statement, so
 * there is no SQL injection. Cart rows are scoped to the logged-in user.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $product_id = (int)($_POST['product_id'] ?? 0);
    $quantity   = max(1, (int)($_POST['quantity'] ?? 1));
    $user_id    = (int)current_user_id();

    if ($product_id > 0) {
        $stmt = mysqli_prepare(
            $conn,
            "INSERT INTO cart_items (user_id, product_id, quantity)
             VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)"
        );
        mysqli_stmt_bind_param($stmt, 'iii', $user_id, $product_id, $quantity);
        mysqli_stmt_execute($stmt);
    }
}

header('Location: cart.php');
exit;
