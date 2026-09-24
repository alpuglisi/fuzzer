<?php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 3 of 10). Closes this cell's
// remaining CWE-89 gap (distinct from vulnerable-3.php/idiomatic-3-altered.php,
// which cover this same cell's CWE-611 XXE group). Genuinely distinct third
// variant from vulnerable-1.php/vulnerable-2.php's mysqli raw-concat/sanitize()
// shape and idiomatic-1.php's mysqli_real_escape_string() shape: a PDO-based
// product-search endpoint that still builds the query by string
// interpolation -- the well-documented real-world misconception that merely
// switching to PDO (rather than using its own bound-parameter API) makes a
// query safe.
$pdo = new PDO('mysql:host=127.0.0.1;dbname=shop', 'REDACTED_DB_USERNAME', 'REDACTED_DB_PASSWORD');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$category = $_GET['category'] ?? '';
$search   = $_GET['search'] ?? '';

// VULNERABLE: PDO is in use, but the query text is still built by direct
// string interpolation instead of PDO's own prepare()/bindParam() API --
// PDO alone provides no protection unless its parameter-binding is actually
// used, which is exactly the real-world gap this pair illustrates.
$sql = "SELECT id, name, price, category FROM products
        WHERE category = '$category' AND name LIKE '%$search%'
        ORDER BY name ASC";
$stmt = $pdo->query($sql);
$products = $stmt->fetchAll(PDO::FETCH_ASSOC);

header('Content-Type: application/json');
echo json_encode($products);
