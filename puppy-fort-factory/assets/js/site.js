// Builds the "Discover" sub-navigation for the JavaScript-rendered pages.
//
// These links are created in the DOM at runtime, so they do NOT appear in the
// static HTML. A basic spider that only parses <a href> tags never discovers
// any of these pages; a real browser shows the whole Discover bar.
(function () {
  var bar = document.getElementById('js-discover');
  if (!bar) { return; }

  var pages = [
    { href: 'deals.php',           label: 'Deals' },
    { href: 'new-arrivals.php',    label: 'New Arrivals' },
    { href: 'bestsellers.php',     label: 'Bestsellers' },
    { href: 'recommendations.php', label: 'Recommended' },
    { href: 'reviews.php',         label: 'Reviews' },
    { href: 'gallery.php',         label: 'Gallery' },
    { href: 'locations.php',       label: 'Store Locations' },
    { href: 'support.php',         label: 'Support' },
    { href: 'wishlist.php',        label: 'Wishlist' },
    { href: 'feedback.php',        label: 'Feedback' }
  ];

  var label = document.createElement('span');
  label.className = 'subnav-label';
  label.textContent = 'Discover:';
  bar.appendChild(label);

  pages.forEach(function (p) {
    var a = document.createElement('a');
    a.href = p.href;
    a.textContent = p.label;
    bar.appendChild(a);
  });
})();
