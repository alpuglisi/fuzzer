<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'New Arrivals';
require __DIR__ . '/includes/header.php';
?>
<h1>New arrivals 🆕</h1>
<!-- JAVASCRIPT-RENDERED: content built in the browser from api/products.php. -->
<p id="na-note">Loading the newest forts…</p>
<div id="new-arrivals" class="grid" data-note="na-note"></div>

<script src="assets/js/catalog.js"></script>
<script>renderCatalog('new-arrivals', { reverse: true, limit: 6 });</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
