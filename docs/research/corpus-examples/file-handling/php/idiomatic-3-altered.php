<?php
// idiomatic-3-altered.php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" -- derived from vulnerable-3-altered.php's own real
// structure. A distinct mitigation technique from idiomatic-2.php's
// realpath-confinement approach: confined deletion via indirect
// reference. The client never supplies a filename or path at all. It
// supplies an opaque numeric attachment id, which is looked up against
// the uploads table for the real on-disk path -- there is no
// user-controlled string that ever reaches unlink(), so there is nothing
// to traverse.
$attachmentId = filter_input(INPUT_POST, 'attachment_id', FILTER_VALIDATE_INT);
if ($attachmentId === false || $attachmentId === null) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid attachment id']);
    exit;
}

$stmt = $pdo->prepare('SELECT storage_path FROM attachments WHERE id = ? AND owner_id = ?');
$stmt->execute([$attachmentId, $currentUserId]);
$row = $stmt->fetch();

if (!$row) {
    http_response_code(404);
    echo json_encode(['error' => 'not found']);
    exit;
}

// storage_path is a server-generated path recorded at upload time (never
// derived from a client-supplied name), so no traversal sequence in a
// request can influence which file gets deleted.
unlink($row['storage_path']);
echo json_encode(['status' => 'deleted']);
