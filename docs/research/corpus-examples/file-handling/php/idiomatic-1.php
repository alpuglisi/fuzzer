<?php
/*
 * Excerpt from WonderCMS/wondercms, index.php, WonderCMS::uploadFileAction()
 * (allowlist + MIME-type check applied before move_uploaded_file()).
 * See manifest.yaml for repo/commit/license provenance. Trimmed to the
 * upload-validation method only; surrounding class/CMS context omitted.
 */

public function uploadFileAction(): void
{
	if (!isset($_FILES['uploadFile']) || !$this->verifyFormActions()) {
		return;
	}
	$allowedMimeTypes = [
		'video/avi',
		'text/css',
		'text/x-asm',
		'application/msword',
		'application/vnd.ms-word',
		'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
		'video/x-flv',
		'image/gif',
		'text/html',
		'image/x-icon',
		'image/jpeg',
		'application/octet-stream',
		'audio/mp4',
		'video/x-matroska',
		'video/quicktime',
		'audio/mpeg',
		'video/mp4',
		'video/mpeg',
		'application/vnd.oasis.opendocument.spreadsheet',
		'application/vnd.oasis.opendocument.text',
		'application/ogg',
		'video/ogg',
		'application/pdf',
		'image/png',
		'application/vnd.ms-powerpoint',
		'application/vnd.openxmlformats-officedocument.presentationml.presentation',
		'application/photoshop',
		'application/rar',
		'image/svg',
		'image/svg+xml',
		'image/avif',
		'image/webp',
		'application/svg+xm',
		'text/plain',
		'application/vnd.ms-excel',
		'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
		'video/webm',
		'video/x-ms-wmv',
		'application/zip',
	];

	$allowedExtensions = [
		'avi',
		'avif',
		'css',
		'doc',
		'docx',
		'flv',
		'gif',
		'htm',
		'html',
		'ico',
		'jpeg',
		'jpg',
		'kdbx',
		'm4a',
		'mkv',
		'mov',
		'mp3',
		'mp4',
		'mpg',
		'ods',
		'odt',
		'ogg',
		'ogv',
		'pdf',
		'png',
		'ppt',
		'pptx',
		'psd',
		'rar',
		'svg',
		'txt',
		'xls',
		'xlsx',
		'webm',
		'webp',
		'wmv',
		'zip',
	];
	if (!isset($_FILES['uploadFile']['error']) || is_array($_FILES['uploadFile']['error'])) {
		$this->alert('danger', 'Invalid parameters.');
		$this->redirect();
	}
	switch ($_FILES['uploadFile']['error']) {
		case UPLOAD_ERR_OK:
			break;
		case UPLOAD_ERR_NO_FILE:
			$this->alert('danger',
				'No file selected. <a data-toggle="wcms-modal" href="#settingsModal" data-target-tab="#files"><b>Re-open file options</b></a>');
			$this->redirect();
			break;
		case UPLOAD_ERR_INI_SIZE:
		case UPLOAD_ERR_FORM_SIZE:
			$this->alert('danger',
				'File too large. Change maximum upload size limit or contact your host. <a data-toggle="wcms-modal" href="#settingsModal" data-target-tab="#files"><b>Re-open file options</b></a>');
			$this->redirect();
			break;
		default:
			$this->alert('danger', 'Unknown error.');
			$this->redirect();
	}
	$mimeType = '';
	$fileName = basename(str_replace(
		['"', "'", '*', '<', '>', '%22', '&#39;', '%', ';', '#', '&', './', '../', '/', '+'],
		'',
		htmlspecialchars(strip_tags($_FILES['uploadFile']['name']))
	));
	$nameExploded = explode('.', $fileName);
	$ext = strtolower(array_pop($nameExploded));

	if (class_exists('finfo')) {
		$finfo = new finfo(FILEINFO_MIME_TYPE);
		$mimeType = $finfo->file($_FILES['uploadFile']['tmp_name']);
	} elseif (function_exists('mime_content_type')) {
		$mimeType = mime_content_type($_FILES['uploadFile']['tmp_name']);
	} elseif (array_key_exists($ext, $allowedExtensions)) {
		$mimeType = $allowedExtensions[$ext];
	}
	if (!in_array($mimeType, $allowedMimeTypes, true) || !in_array($ext, $allowedExtensions)) {
		$this->alert('danger',
			'File format is not allowed. <a data-toggle="wcms-modal" href="#settingsModal" data-target-tab="#files"><b>Re-open file options</b></a>');
		$this->redirect();
	}
	if (!move_uploaded_file($_FILES['uploadFile']['tmp_name'], $this->filesPath . '/' . $fileName)) {
		$this->alert('danger', 'Failed to move uploaded file.');
	}
	$this->alert('success',
		'File uploaded. <a data-toggle="wcms-modal" href="#settingsModal" data-target-tab="#files"><b>Open file options to see your uploaded file</b></a>');
	$this->redirect();
}
