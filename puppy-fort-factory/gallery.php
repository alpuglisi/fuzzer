<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Gallery';
require __DIR__ . '/includes/header.php';
?>
<h1>Fort gallery 📸</h1>
<!-- JAVASCRIPT-RENDERED: captions come from the inline data island below. -->
<div id="gallery" class="grid"></div>

<script id="gallery-data" type="application/json">
[
  {"title":"The Grand Kennel Keep","caption":"Four towers, one very smug corgi."},
  {"title":"Moat with a View","caption":"Kibble moat, now with drawbridge access."},
  {"title":"Bacon Battlements at Dusk","caption":"Structural integrity: about four minutes."},
  {"title":"Watchtower Naptime","caption":"Vigilance is tiring work."},
  {"title":"Camo Fort in the Wild","caption":"You cannot see it. Neither can the puppy."},
  {"title":"Squeaky Drawbridge Mk II","caption":"Now 20% squeakier."}
]
</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('gallery-data').textContent);
  var box = document.getElementById('gallery');
  data.forEach(function (g) {
    var card = document.createElement('div');
    card.className = 'card';
    var h = document.createElement('h3');
    h.textContent = g.title;      // safe: textContent
    var p = document.createElement('p');
    p.textContent = g.caption;    // safe: textContent
    card.appendChild(h);
    card.appendChild(p);
    box.appendChild(card);
  });
})();
</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
