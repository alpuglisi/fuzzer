<?php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". Missing idiomatic counterpart for vulnerable-3.php's
// CWE-611 XXE (this cell's own manifest.yaml entry:
// rubennati/vulnerable-php-code-examples' DOMDocument::loadXML() call
// with LIBXML_NOENT set on raw user-supplied XML). Minimal-pair
// discipline: identical input source ($_POST['xml']), identical
// DOMDocument/loadXML/saveXML shape. The ONLY mechanism difference is
// that external entity resolution is disabled instead of enabled: no
// LIBXML_NOENT flag is passed, and LIBXML_NONET is set instead (blocking
// any network-based entity resolution even if a future edit reintroduces
// entity substitution) -- closing the XXE hole vulnerable-3.php leaves
// open.

// XML parsed safely — external entities are NOT enabled
$xml = $_POST['xml'] ?? '';

$doc = new DOMDocument();
// SAFE: LIBXML_NOENT (the flag that tells libxml to substitute entity
// references, including external ones, inline) is deliberately omitted.
// LIBXML_NONET additionally blocks any network access libxml might
// otherwise attempt while parsing, as defense in depth against a future
// edit that re-enables entity substitution.
$doc->loadXML($xml, LIBXML_NONET);

echo $doc->saveXML();
