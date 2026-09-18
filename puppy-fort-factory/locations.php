<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Store Locations';
require __DIR__ . '/includes/header.php';
?>
<h1>Where to find us 📍</h1>
<!-- JAVASCRIPT-RENDERED: the store list is built from the inline data island. -->
<div id="locations"></div>

<script id="location-data" type="application/json">
[
  {"city":"Barkford",   "address":"1 Kennel Lane",   "hours":"9-6 daily"},
  {"city":"Fetchville",  "address":"22 Fetch Street", "hours":"10-7 Mon-Sat"},
  {"city":"Wagtown",     "address":"8 Bark Avenue",   "hours":"9-5 Mon-Fri"},
  {"city":"Snoutley",    "address":"4 Biscuit Road",  "hours":"11-8 daily"}
]
</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('location-data').textContent);
  var box = document.getElementById('locations');
  data.forEach(function (loc) {
    var div = document.createElement('div');
    div.className = 'bio';
    var h = document.createElement('strong');
    h.textContent = loc.city;
    var p = document.createElement('p');
    p.textContent = loc.address + ' — ' + loc.hours;   // safe: textContent
    div.appendChild(h);
    div.appendChild(p);
    box.appendChild(div);
  });
})();
</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
