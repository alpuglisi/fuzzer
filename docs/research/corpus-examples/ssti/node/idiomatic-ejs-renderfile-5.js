// Manufactured, representative of safe EJS usage: renderFile() loads a
// fixed template asset from disk by path, never a runtime string.
const ejs = require('ejs');

function renderPlaylistPage(playlistName, tracks) {
  return ejs.renderFile(__dirname + '/views/playlist.ejs', { playlistName, tracks });
}
