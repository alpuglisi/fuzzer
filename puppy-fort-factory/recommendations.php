<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Recommended';
require __DIR__ . '/includes/header.php';
?>
<h1>Recommended for your pup 🐾</h1>
<!-- JAVASCRIPT-RENDERED: content built in the browser from api/products.php. -->
<p id="rec-note">Fetching recommendations…</p>
<div id="recommendations" class="grid" data-note="rec-note"></div>

<script src="assets/js/catalog.js"></script>
<script>renderCatalog('recommendations', { discount: 0.1, limit: 8 });</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
