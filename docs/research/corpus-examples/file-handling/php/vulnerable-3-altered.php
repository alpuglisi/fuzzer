<?php
// vulnerable-3-altered.php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". A distinct sink from this file's readfile()-based download
// pair (vulnerable-2.php/idiomatic-2.php): file deletion. The
// client-supplied 'file' POST field is joined directly onto the uploads
// directory and passed to unlink() with no validation or confinement of
// any kind.
$targetFile = $_POST['file'];
$path = __DIR__ . '/uploads/' . $targetFile;

if (file_exists($path)) {
    unlink($path);
    echo json_encode(['status' => 'deleted']);
} else {
    http_response_code(404);
    echo json_encode(['error' => 'not found']);
}
