<?php
// vulnerable-4-altered.php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". A distinct upload-validation idiom from this file's
// extension+finfo-allowlist pair (vulnerable-1.php/idiomatic-1.php):
// avatar upload that trusts the client-declared Content-Type of the
// multipart part alone (never sniffing or re-encoding the actual image
// bytes) before saving the file with its original extension.
$type = $_FILES['avatar']['type'] ?? '';

if (strpos($type, 'image/') === 0) {
    $ext = substr($type, strlen('image/'));
    $dest = __DIR__ . '/avatars/' . uniqid('avatar_', true) . '.' . $ext;
    move_uploaded_file($_FILES['avatar']['tmp_name'], $dest);
    echo json_encode(['status' => 'uploaded', 'path' => $dest]);
} else {
    http_response_code(415);
    echo json_encode(['error' => 'unsupported type']);
}
