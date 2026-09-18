<?php
require_once __DIR__ . '/../includes/db.php';

/*
 * JSON data source for the JavaScript-rendered pages (deals.php).
 *
 * SECURE: the optional category filter uses a prepared statement, so there is
 * no SQL injection. Output is JSON, not HTML, so a basic (HTML-only) spider
 * finds no links here even if it reaches this URL.
 */
header('Content-Type: application/json; charset=utf-8');

$category = $_GET['category'] ?? '';
if ($category !== '') {
    $stmt = mysqli_prepare(
        $conn,
        "SELECT id, name, price, description, category FROM products WHERE category = ? ORDER BY name"
    );
    mysqli_stmt_bind_param($stmt, 's', $category);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
} else {
    $res = mysqli_query(
        $conn,
        "SELECT id, name, price, description, category FROM products ORDER BY name"
    );
}

$out = [];
while ($row = mysqli_fetch_assoc($res)) {
    $out[] = [
        'id'          => (int)$row['id'],
        'name'        => $row['name'],
        'price'       => (float)$row['price'],
        'description' => $row['description'],
        'category'    => $row['category'],
    ];
}

echo json_encode($out);
