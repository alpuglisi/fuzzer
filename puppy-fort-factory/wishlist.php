<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Wishlist';
require __DIR__ . '/includes/header.php';
?>
<h1>Your wishlist 💝</h1>
<!--
  JAVASCRIPT-RENDERED: the wishlist is kept in the browser (localStorage) and
  rendered client-side, so it never appears in the static HTML.
-->
<p id="wl-note">Loading your wishlist…</p>
<div id="wishlist" class="grid"></div>

<script src="assets/js/catalog.js"></script>
<script>
(function () {
  // Demo: if nothing is saved yet, seed a sample wishlist so the page has content.
  try {
    if (!localStorage.getItem('pff_wishlist')) {
      localStorage.setItem('pff_wishlist', JSON.stringify([1, 3, 6]));
    }
  } catch (e) { /* storage may be unavailable; page still works */ }

  var note = document.getElementById('wl-note');
  if (note) { note.textContent = 'Saved forts (kept in your browser):'; }

  // Reuse the shared renderer to show all products, then the browser could
  // filter by saved ids. For the demo we simply render the catalogue.
  renderCatalog('wishlist', { limit: 6 });
})();
</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
