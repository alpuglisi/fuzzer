<?php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 3 of 10). Derived from
// vulnerable-4-altered.php's real PDO structure. Minimal-pair discipline:
// identical PDO connection setup, identical inputs, identical output
// shape. The ONLY mechanism difference is the query construction: this file
// uses PDO's own prepare()/execute() named-placeholder binding for both
// dynamic values, instead of interpolating them directly into the SQL text.
$pdo = new PDO('mysql:host=127.0.0.1;dbname=shop', 'REDACTED_DB_USERNAME', 'REDACTED_DB_PASSWORD');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$category = $_GET['category'] ?? '';
$search   = $_GET['search'] ?? '';

// IDIOMATIC: both dynamic values are bound as query parameters through
// PDO's own prepare()/execute() API -- the driver sends the SQL text and
// the values to the server as separate protocol messages, so neither value
// can alter the query's structure.
$stmt = $pdo->prepare(
    "SELECT id, name, price, category FROM products
     WHERE category = :category AND name LIKE :search
     ORDER BY name ASC"
);
$stmt->execute([
    'category' => $category,
    'search'   => '%' . $search . '%',
]);
$products = $stmt->fetchAll(PDO::FETCH_ASSOC);

header('Content-Type: application/json');
echo json_encode($products);
