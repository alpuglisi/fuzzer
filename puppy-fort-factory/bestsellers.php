<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Bestsellers';
require __DIR__ . '/includes/header.php';
?>
<h1>Bestsellers ⭐</h1>
<!-- JAVASCRIPT-RENDERED: content built in the browser from api/products.php. -->
<p id="bs-note">Loading the crowd favourites…</p>
<div id="bestsellers" class="grid" data-note="bs-note"></div>

<script src="assets/js/catalog.js"></script>
<script>renderCatalog('bestsellers', { limit: 6 });</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
