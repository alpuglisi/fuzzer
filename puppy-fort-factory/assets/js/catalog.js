// Shared client-side product renderer for the JavaScript-rendered pages.
//
// It fetches api/products.php and builds the product cards and their
// product.php links in the browser. None of this appears in the static HTML,
// so a basic HTML-only spider sees an empty container.
window.renderCatalog = function (containerId, opts) {
  opts = opts || {};
  var container = document.getElementById(containerId);
  if (!container) { return; }

  var url = 'api/products.php';
  if (opts.category) { url += '?category=' + encodeURIComponent(opts.category); }

  fetch(url)
    .then(function (r) { return r.json(); })
    .then(function (items) {
      if (opts.reverse) { items = items.slice().reverse(); }
      if (opts.limit) { items = items.slice(0, opts.limit); }

      var html = items.map(function (p) {
        var price = Number(p.price).toFixed(2);
        var deal = opts.discount ? ' <s>$' + price + '</s> $' + (p.price * (1 - opts.discount)).toFixed(2) : '$' + price;
        return '<div class="card">'
          + '<h3><a href="product.php?id=' + p.id + '">' + esc(p.name) + '</a></h3>'
          + '<p class="price">' + deal + '</p>'
          + '<p>' + esc(p.description) + '</p>'
          + '<a class="btn" href="product.php?id=' + p.id + '">View</a>'
          + '</div>';
      }).join('');

      container.innerHTML = html || '<p>Nothing here yet.</p>';
      var noteId = container.getAttribute('data-note');
      if (noteId) { var n = document.getElementById(noteId); if (n) { n.remove(); } }
    })
    .catch(function () {
      container.innerHTML = '<p class="error">Could not load items.</p>';
    });

  // Safe rendering: all product text is escaped before insertion.
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
};
