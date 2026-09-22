<?php
/*
 * Excerpt from RagnarTheGreat/Serenity-Share, share.php (the "$_GET['file']"
 * download branch): confines the resolved path to the share directory via
 * realpath()+strpos() before readfile(). See manifest.yaml for repo/commit/
 * license provenance. Trimmed to the download-validation branch only;
 * surrounding session/share-management code omitted.
 */

if (isset($_GET['file'])) {
    // Find the file metadata first to get the correct path
    $fileKey = null;
    $fileData = null;

    foreach ($metadata['files'] as $index => $file) {
        if ($file['name'] === $_GET['file']) {
            $fileKey = $index;
            $fileData = $file;
            break;
        }
    }

    if (!$fileData) {
        die("File not found in share.");
    }

    $filename = $fileData['name'];
    $filepath = $sharePath . '/' . $fileData['path'];

    // Validate that the file exists and is within the share directory
    if (!file_exists($filepath) || !is_file($filepath) ||
        strpos(realpath($filepath), realpath($sharePath)) !== 0) {
        die("File not found or access denied.");
    }

    // Get file mime type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $filepath);
    finfo_close($finfo);

    // Set headers for download
    header('Content-Type: ' . $mime_type);
    header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: no-cache');

    // Output file
    readfile($filepath);
    exit;
}
