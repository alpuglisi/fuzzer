<?php
// Excerpt of Twig, src/Environment.php (BSD-3-Clause). Source: repo
// twigphp/Twig, commit a8900116997903a2170ec8055eec96432a4c8ad5 --
// createTemplate()'s own real docblock says "This method should not be
// used as a generic way to load templates." This entry is a manufactured
// caller that does exactly that.

// A "customize your channel description" feature lets a user submit
// Twig syntax directly, compiled and rendered per request.
$twig = new \Twig\Environment($loader);

// createTemplate() compiles $userSuppliedDescription as Twig source --
// e.g. "{{ app.request.server.all() }}" or a chain reaching
// _self.env.registerUndefinedFilterCallback('exec') in older Twig
// versions -- real, documented Twig SSTI payload shapes.
$template = $twig->createTemplate($userSuppliedDescription);
echo $template->render(['channel' => $channel]);
