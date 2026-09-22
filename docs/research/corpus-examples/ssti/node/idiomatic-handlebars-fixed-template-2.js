// Manufactured, representative of safe Handlebars usage: the template
// string is a fixed, developer-authored asset; only the *data* passed to
// it varies per request.
const Handlebars = require('handlebars');
const fs = require('fs');

const source = fs.readFileSync(__dirname + '/templates/channel-page.hbs', 'utf8');
const template = Handlebars.compile(source); // compiled once, at startup

function renderChannelPage(channel) {
  return template({ channel }); // only data varies
}
