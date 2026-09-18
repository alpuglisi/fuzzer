// Injects navigation links to the JavaScript-rendered pages into the header.
//
// These links are created in the DOM at runtime, so they do NOT appear in the
// static HTML. A basic spider that only parses <a href> tags from the raw
// markup never discovers deals.php or reviews.php; a real browser shows them.
(function () {
  var nav = document.getElementById('js-nav');
  if (!nav) { return; }

  var pages = [
    { href: 'deals.php',   label: 'Deals' },
    { href: 'reviews.php', label: 'Reviews' }
  ];

  pages.forEach(function (p) {
    var a = document.createElement('a');
    a.href = p.href;
    a.textContent = p.label;
    nav.appendChild(a);
  });
})();
