<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Reviews';
require __DIR__ . '/includes/header.php';
?>
<h1>What pups are saying 🐕</h1>

<!--
  JAVASCRIPT-RENDERED PAGE.
  The review text lives in a JSON data island and is rendered by the browser,
  so a basic HTML-only spider sees no review content and no anchors.

  It also contains a DOM-BASED XSS via the URL fragment (see the script). The
  fragment never reaches the server, so a server-side scanner and the raw HTML
  both miss it too.
-->
<div id="greeting"></div>
<div id="reviews"></div>

<script id="review-data" type="application/json">
[
  {"author":"Rex",   "stars":5, "text":"My fort survived three teething puppies. Impregnable."},
  {"author":"Luna",  "stars":4, "text":"The squeaky drawbridge is a menace at 6am. Great fort though."},
  {"author":"Biscuit","stars":5,"text":"Chew-proof walls are no match for me, but I respect the effort."},
  {"author":"Pepper","stars":3, "text":"Bacon battlements were gone in four minutes. Please sell refills."},
  {"author":"Scout", "stars":5, "text":"Best watchtower in the neighbourhood. I see all squirrels now."}
]
</script>

<script>
(function () {
  // Render reviews from the inline data island. Text goes in via textContent,
  // so the reviews themselves are not an XSS vector.
  var data = JSON.parse(document.getElementById('review-data').textContent);
  var box = document.getElementById('reviews');
  data.forEach(function (r) {
    var stars = '★'.repeat(r.stars) + '☆'.repeat(5 - r.stars);
    var el = document.createElement('div');
    el.className = 'bio';
    el.innerHTML = '<strong></strong> <span class="stars"></span><p></p>';
    el.querySelector('strong').textContent = r.author;
    el.querySelector('.stars').textContent = ' ' + stars;
    el.querySelector('p').textContent = r.text;
    box.appendChild(el);
  });

  // !! VULNERABLE: DOM-based XSS.
  // A personalised greeting is read from the URL fragment and written with
  // innerHTML without sanitisation. The payload stays client-side, e.g.:
  //   reviews.php#author=<img src=x onerror=alert(document.cookie)>
  var m = location.hash.match(/author=([^&]*)/);
  if (m) {
    var name = decodeURIComponent(m[1]);
    document.getElementById('greeting').innerHTML =
      '<p class="notice ok">Thanks for your review, ' + name + '!</p>';
  }
})();
</script>

<?php require __DIR__ . '/includes/footer.php'; ?>
