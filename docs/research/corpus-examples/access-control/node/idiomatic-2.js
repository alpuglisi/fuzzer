// Excerpt from routes/index.js (single route only; module wrapper/other
// routes trimmed). Full file is much larger. MIT licensed.
// Source: GuusK/disruptIT @ ad09689d5c006ee5611e5b308cabfba1a9b998c2
//
// Contrast with vulnerable-2.js, a few lines below this one in the SAME
// file in the same commit (/tickets/:id/barcode): that route has neither
// the `auth` middleware nor an ownership check. This route requires auth
// AND checks that the ticket's owner email matches the logged-in user
// before rendering it.

var Ticket = require('../models/Ticket');

function auth(req, res, next) {
  if (!req.user) {
    req.session.lastPage = req.path;
    req.flash('info', 'You have to log in to visit page ' + req.path);
    return res.redirect('/login');
  }
  next();
}

router.get('/tickets/:id', auth, function (req, res, next) {
  Ticket.findById(req.params.id).populate('ownedBy').exec(function (err, ticket) {
    if (err) { err.code = 403; return next(err); }
    if (!ticket || !ticket.ownedBy || ticket.ownedBy.email !== req.session.passport.user) {
      var error = new Error("Forbidden");
      error.code = 403;
      return next(error);
    }
    res.render('tickets/ticket', {ticket: ticket});
  });
});
