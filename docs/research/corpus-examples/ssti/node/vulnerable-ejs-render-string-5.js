// Manufactured vulnerable variant, derived from
// idiomatic-ejs-renderfile-5.js. ejs.render() on a user-supplied string
// compiles arbitrary EJS -- EJS templates can embed raw JavaScript via
// scriptlet tags (<% %>), a well-documented real SSTI-to-RCE surface
// distinct from Handlebars' helper-lookup gadget-chain style.
const ejs = require('ejs');

function renderPlaylistPage(playlistName, userSuppliedDescription) {
  // <%- and <% scriptlet tags in userSuppliedDescription run as raw
  // JavaScript during render, e.g.
  // "<%- global.process.mainModule.require('child_process').execSync('id') %>".
  return ejs.render(userSuppliedDescription, { playlistName });
}
