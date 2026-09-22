// Excerpt from routes/index.js (barcode route only; module wrapper/other
// routes trimmed). Full file is much larger. MIT licensed.
// Source: GuusK/disruptIT @ ad09689d5c006ee5611e5b308cabfba1a9b998c2
//
// Contrast with idiomatic-2.js, the very next route in the SAME file in
// the same commit: /tickets/:id (a few lines above this one) requires the
// `auth` middleware AND checks `ticket.ownedBy.email !== req.session.passport.user`
// before rendering. This route, immediately below it, has neither: no auth
// middleware and no ownership check, so anyone can fetch any ticket's
// barcode image by guessing/incrementing :id (IDOR / forced browsing).

var Barc = require('barcode-generator');
var barc = new Barc({
  hri: false
});

router.get('/tickets/:id/barcode', function (req, res) {
  res.set('Content-Type', 'image/png');
  res.send(barc.code128(req.params.id, 440, 50));
});
