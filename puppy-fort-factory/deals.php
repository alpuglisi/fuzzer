<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Deals';
require __DIR__ . '/includes/header.php';
?>
<h1>Today's fort deals 🦴</h1>

<!--
  JAVASCRIPT-RENDERED PAGE.
  The raw HTML below contains no product data and no product links. Everything
  is fetched from api/products.php and built in the browser, so a basic spider
  that does not execute JavaScript sees an empty shell and discovers nothing.
-->
<p id="deals-note">Loading the latest deals…</p>
<div id="deals" class="grid"></div>

<script>
(function () {
  var container = document.getElementById('deals');

  fetch('api/products.php')
    .then(function (r) { return r.json(); })
    .then(function (items) {
      var html = '';
      items.slice(0, 6).forEach(function (p) {
        var deal = (p.price * 0.8).toFixed(2);
        html += '<div class="card">'
          + '<h3><a href="product.php?id=' + p.id + '">' + escapeHtml(p.name) + '</a></h3>'
          + '<p class="price">Deal $' + deal + ' <s>$' + p.price.toFixed(2) + '</s></p>'
          + '<p>' + escapeHtml(p.description) + '</p>'
          + '<a class="btn" href="product.php?id=' + p.id + '">View</a>'
          + '</div>';
      });
      container.innerHTML = html || '<p>No deals right now.</p>';
      var note = document.getElementById('deals-note');
      if (note) { note.remove(); }
    })
    .catch(function () {
      container.innerHTML = '<p class="error">Could not load deals.</p>';
    });

  // Safe rendering: product text is escaped before insertion (no XSS here).
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
})();
</script>

<?php require __DIR__ . '/includes/footer.php'; ?>
