<?php
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Feedback';
require __DIR__ . '/includes/header.php';
?>
<h1>Send us feedback 📝</h1>

<!--
  JAVASCRIPT-RENDERED PAGE.
  The form is built in the browser, so a basic spider sees no form fields.

  It also contains a DOM-BASED XSS via the query string: the `ref` parameter is
  read on the client and written with innerHTML. The server never uses `ref`, so
  a server-side scanner sees no reflection; only a JS-executing client triggers it:
    feedback.php?ref=<img src=x onerror=alert(document.domain)>
-->
<div id="fb-status"></div>
<div id="fb-form"></div>

<script>
(function () {
  var box = document.getElementById('fb-form');
  box.innerHTML =
      '<form class="stack" onsubmit="return false">'
    + '  <label>Your name <input id="fb-name" type="text"></label>'
    + '  <label>Message <textarea id="fb-msg"></textarea></label>'
    + '  <p><button class="btn" type="button" id="fb-send">Send feedback</button></p>'
    + '</form>'
    + '<div id="fb-echo"></div>';

  document.getElementById('fb-send').addEventListener('click', function () {
    var msg = document.getElementById('fb-msg').value;
    // Safe echo of the user's own message (textContent, not innerHTML).
    document.getElementById('fb-echo').textContent = msg ? ('Thanks! You said: ' + msg) : '';
  });

  // !! VULNERABLE: DOM-based XSS via the query string.
  var ref = new URLSearchParams(location.search).get('ref');
  if (ref) {
    document.getElementById('fb-status').innerHTML =
      '<p class="notice ok">Thanks for visiting from ' + ref + '!</p>';
  }
})();
</script>
<?php require __DIR__ . '/includes/footer.php'; ?>
