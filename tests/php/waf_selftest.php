<?php
/**
 * Offline self-test driver for the lab WAF (`L-P3.3c-CUT`: re-homed from the
 * retired `puppy-fort-factory/tests/waf_selftest.php`).
 *
 * Reads a JSON object of {name: input_string} from stdin, checks each input against
 * the committed ruleset (`lab/waf-rules.json`), and prints
 * {name: {"hits": [rule_ids], "clean": sanitized}}. Used by tests/test_lab_waf.py so
 * the filter logic is exercised offline with the same PHP the container runs.
 *
 * Requires `WafFilter.php` directly -- the same, framework-free class the real
 * `FzlWaf` middleware calls (`app/Http/Middleware/FzlWaf.php`, in the php_laravel
 * stack skeleton) -- rather than a second, independently-maintained copy of the
 * filtering logic (PA-0003/PA-0021).
 */
require __DIR__ . '/../../fuzzlab/labgen/emitters/php_laravel/stack/skeleton/app/Support/WafFilter.php';

use App\Support\WafFilter;

$rules = WafFilter::loadRules(__DIR__ . '/../../lab/waf-rules.json');
$cases = json_decode((string) file_get_contents('php://stdin'), true) ?: [];
$out = [];
foreach ($cases as $name => $value) {
    $res = WafFilter::checkValue((string) $value, $rules);
    $out[$name] = ['hits' => array_column($res['hits'], 'id'), 'clean' => $res['clean']];
}
echo json_encode($out);
