<?php
// Manufactured, representative of safe Smarty usage: display() takes a
// fixed, developer-authored .tpl file name, never a runtime string.
$smarty = new Smarty();
$smarty->assign('episodeTitle', $episodeTitle);
$smarty->display('episode-page.tpl'); // fixed template file
