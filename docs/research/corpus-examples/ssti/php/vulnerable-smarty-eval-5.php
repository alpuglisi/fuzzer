<?php
// Manufactured vulnerable variant, derived from
// idiomatic-smarty-fixed-template-4.php. Smarty's own fetch()/eval-string
// APIs compile a runtime string as template source -- Smarty's own
// security guidance warns this must never take user input, since the
// default (unsandboxed) Smarty configuration allows PHP function calls
// from template expressions.
$smarty = new Smarty();
$smarty->assign('episodeTitle', $episodeTitle);

// $userSuppliedBio is compiled and evaluated as Smarty template source
// -- a Smarty template can call PHP functions directly by default
// (e.g. {php}system($_GET['c']){/php} in older Smarty, or a
// {$smarty.template_object->...} object-access chain in newer versions).
echo $smarty->fetch('eval:' . $userSuppliedBio);
