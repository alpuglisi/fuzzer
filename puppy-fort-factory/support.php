<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Support';
require __DIR__ . '/includes/header.php';
?>
<h1>Support centre 🛟</h1>
<!-- JAVASCRIPT-RENDERED: help topics are built from the inline data island. -->
<div id="support"></div>

<script id="support-data" type="application/json">
[
  {"q":"My drawbridge won't stop squeaking.","a":"That is a feature. If it stops, contact us."},
  {"q":"How do I reset my fort?","a":"Disassemble, praise the puppy, reassemble."},
  {"q":"Where is my order?","a":"Use the Track Order page with your order number."},
  {"q":"Can I return a chewed fort?","a":"Within 30 days, if territory has not been declared."}
]
</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('support-data').textContent);
  var box = document.getElementById('support');
  data.forEach(function (item) {
    var wrap = document.createElement('div');
    wrap.className = 'bio';
    var q = document.createElement('strong');
    q.textContent = item.q;      // safe: textContent
    var a = document.createElement('p');
    a.textContent = item.a;      // safe: textContent
    wrap.appendChild(q);
    wrap.appendChild(a);
    box.appendChild(wrap);
  });
})();
</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
