<?php
require_once __DIR__ . '/../config/config.php';

// mysqli connection shared by every page.
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if (!$conn) {
    http_response_code(500);
    die('Database connection failed: ' . mysqli_connect_error());
}
mysqli_set_charset($conn, 'utf8mb4');
