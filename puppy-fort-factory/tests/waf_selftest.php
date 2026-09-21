<?php
/**
 * Offline self-test driver for the lab WAF (see includes/waf.php).
 *
 * Reads a JSON object of {name: input_string} from stdin, checks each input against
 * the committed ruleset, and prints {name: {"hits": [rule_ids], "clean": sanitized}}.
 * Used by tests/test_lab_waf.py so the filter logic is exercised offline with the same
 * PHP the container runs. Requiring waf.php is safe: its bootstrap is a no-op unless
 * PFF_WAF is enabled (which it is not here).
 */
require __DIR__ . '/../includes/waf.php';

$rules = pff_waf_load_rules(__DIR__ . '/../config/waf-rules.json');
$cases = json_decode((string) file_get_contents('php://stdin'), true) ?: [];
$out = [];
foreach ($cases as $name => $value) {
    $res = pff_waf_check_value((string) $value, $rules);
    $out[$name] = ['hits' => array_column($res['hits'], 'id'), 'clean' => $res['clean']];
}
echo json_encode($out);
