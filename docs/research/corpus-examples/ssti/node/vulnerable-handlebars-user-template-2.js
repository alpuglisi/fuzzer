// Manufactured vulnerable variant, derived from
// idiomatic-handlebars-fixed-template-2.js. Compiles a per-request,
// user-supplied string as the Handlebars template itself.
const Handlebars = require('handlebars');

function renderChannelPage(channel, userSuppliedLayout) {
  // Handlebars.compile() on attacker-controlled text: Handlebars has a
  // well-documented real SSTI/RCE history via helper-lookup gadget
  // chains (e.g. the publicly disclosed "constructor" chain CVEs), not
  // merely a theoretical concern.
  const template = Handlebars.compile(userSuppliedLayout);
  return template({ channel });
}
