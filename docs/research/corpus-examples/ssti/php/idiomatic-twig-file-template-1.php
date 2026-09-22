<?php
// Excerpt of Twig, src/Environment.php (BSD-3-Clause). Source: repo
// twigphp/Twig, commit a8900116997903a2170ec8055eec96432a4c8ad5.
// This is real, unmodified Twig usage: templates are loaded by NAME from
// a configured loader (a filesystem directory of .twig files an
// application developer controls), never compiled from request data.

$twig = new \Twig\Environment($loader, ['cache' => '/tmp/twig_cache']);

// $templateName is one of a fixed set of file names the application
// ships (e.g. "channel-page.twig"); it is never derived from user input.
echo $twig->render($templateName, ['channel' => $channel]);
