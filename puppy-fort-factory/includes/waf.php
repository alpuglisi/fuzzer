<?php
/**
 * Lab WAF — a configurable request pre-filter for Ryder's Puppy Fort Factory.
 *
 * This is a DELIBERATELY NAIVE, signature-based filter for the security lab. Its
 * purpose is to give the toolkit's Phase 8 mutation engine a real, controllable
 * target to learn to bypass (filter-transformation learning, FR-MUT-3) — it is NOT
 * a real WAF and provides no real protection.
 *
 * DEFAULT OFF. With PFF_WAF unset/off this file is a no-op, so the app behaves
 * exactly as before and every existing ground-truth label stays valid. It is wired
 * globally via php.ini `auto_prepend_file` (see lab/web.Dockerfile), so it runs
 * before every request without editing any page — and does nothing until enabled.
 *
 * Configuration (environment variables, read per request — no rebuild to toggle):
 *   PFF_WAF        on|off        (default off)
 *   PFF_WAF_MODE   block|sanitize|log   (default block)
 *   PFF_WAF_RULES  path to the ruleset JSON (default config/waf-rules.json)
 *
 * Modes:
 *   block     — a matching request gets 403 and stops (evasion target: avoid the rule)
 *   sanitize  — the matched fragment is stripped from the input the app sees
 *               (evasion target: learn what the filter removes and adapt)
 *   log       — matches are logged only; the request proceeds unchanged (observe)
 */

/** Check one string against the ruleset. Returns hits + the sanitized string. */
function pff_waf_check_value(string $value, array $rules): array
{
    $hits = [];
    $clean = $value;
    foreach ($rules as $rule) {
        $pattern = $rule['pattern'] ?? '';
        if ($pattern === '' || @preg_match($pattern, $value) !== 1) {
            continue;
        }
        $hits[] = ['id' => $rule['id'] ?? '?', 'category' => $rule['category'] ?? '?',
                   'action' => $rule['action'] ?? ''];
        $clean = preg_replace($pattern, '', $clean);   // what 'sanitize' would keep
    }
    return ['hits' => $hits, 'clean' => $clean];
}

/** Load and validate the ruleset JSON; returns [] on any problem (fail open: lab). */
function pff_waf_load_rules(string $path): array
{
    if (!is_file($path)) {
        return [];
    }
    $data = json_decode((string) file_get_contents($path), true);
    return is_array($data) && isset($data['rules']) && is_array($data['rules'])
        ? $data['rules'] : [];
}

/** Recursively collect string leaves of a request array as [path, value]. */
function pff_waf_leaves($arr, string $prefix, array &$out): void
{
    foreach ((array) $arr as $key => $val) {
        $path = $prefix === '' ? (string) $key : "$prefix.$key";
        if (is_array($val)) {
            pff_waf_leaves($val, $path, $out);
        } elseif (is_string($val)) {
            $out[] = [$path, $val];
        }
    }
}

/**
 * The bootstrap: apply the filter to the live request when enabled. Runs on include
 * (auto_prepend_file). A no-op unless PFF_WAF is enabled, so the default app is
 * unchanged.
 */
(function (): void {
    $on = strtolower((string) (getenv('PFF_WAF') ?: 'off'));
    if (!in_array($on, ['1', 'on', 'true', 'yes'], true)) {
        return;                                        // default OFF — no-op
    }
    $mode = strtolower((string) (getenv('PFF_WAF_MODE') ?: 'block'));
    $rulesPath = getenv('PFF_WAF_RULES') ?: __DIR__ . '/../config/waf-rules.json';
    $rules = pff_waf_load_rules($rulesPath);
    if (!$rules) {
        return;
    }

    // Scan GET, POST, and cookie values (where injected input arrives).
    $sources = ['GET' => &$_GET, 'POST' => &$_POST, 'COOKIE' => &$_COOKIE];
    foreach ($sources as $name => &$bag) {
        $leaves = [];
        pff_waf_leaves($bag, '', $leaves);
        foreach ($leaves as [$path, $value]) {
            $res = pff_waf_check_value($value, $rules);
            if (!$res['hits']) {
                continue;
            }
            $effective = $mode;
            foreach ($res['hits'] as $h) {              // a rule may force its own action
                if (!empty($h['action'])) {
                    $effective = $h['action'];
                }
            }
            error_log(sprintf('[pff-waf] %s param %s matched %s (mode=%s)', $name, $path,
                implode(',', array_column($res['hits'], 'id')), $effective));
            if ($effective === 'log') {
                continue;
            }
            if ($effective === 'sanitize') {
                pff_waf_set_leaf($bag, $path, $res['clean']);
                continue;
            }
            // block (default)
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
            echo "<!doctype html><title>Request blocked</title>"
               . "<h1>403 — request blocked by the lab filter</h1>"
               . "<p>Matched rule(s): "
               . htmlspecialchars(implode(', ', array_column($res['hits'], 'id')))
               . "</p>";
            exit;
        }
    }
    unset($bag);
})();

/** Write a sanitized value back to a dotted leaf path of a request superglobal. */
function pff_waf_set_leaf(array &$bag, string $path, string $value): void
{
    $keys = explode('.', $path);
    $ref = &$bag;
    foreach ($keys as $i => $key) {
        if ($i === count($keys) - 1) {
            $ref[$key] = $value;
        } elseif (isset($ref[$key]) && is_array($ref[$key])) {
            $ref = &$ref[$key];
        } else {
            return;
        }
    }
}
