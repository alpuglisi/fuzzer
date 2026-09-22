<?php

namespace App\Support;

/**
 * Pure WAF filtering logic, factored out of the `FzlWaf` middleware
 * (`L-P3.3c-CUT`) so it can be exercised standalone -- no Illuminate/Laravel
 * framework bootstrap required -- by both the middleware itself and
 * `tests/test_lab_waf.py`'s offline self-test driver
 * (`tests/php/waf_selftest.php`), per PA-0003/PA-0021: one shared
 * implementation, two callers, never a second copy that could drift from
 * what the middleware actually enforces.
 *
 * Deliberately framework-free (no `Illuminate\*` types anywhere in this
 * class) so a plain `php` CLI script can `require` this file directly and
 * call it, exactly like the retired `puppy-fort-factory/includes/waf.php`'s
 * standalone functions could.
 */
class WafFilter
{
    /** Check one string against the ruleset. Returns hits + the sanitized string. */
    public static function checkValue(string $value, array $rules): array
    {
        $hits = [];
        $clean = $value;
        foreach ($rules as $rule) {
            $pattern = $rule['pattern'] ?? '';
            if ($pattern === '' || @preg_match($pattern, $value) !== 1) {
                continue;
            }
            $hits[] = [
                'id' => $rule['id'] ?? '?',
                'category' => $rule['category'] ?? '?',
                'action' => $rule['action'] ?? '',
            ];
            $clean = preg_replace($pattern, '', $clean);   // what 'sanitize' would keep
        }
        return ['hits' => $hits, 'clean' => $clean];
    }

    /** Load and validate the ruleset JSON; returns [] on any problem (fail open: lab). */
    public static function loadRules(string $path): array
    {
        if (!is_file($path)) {
            return [];
        }
        $data = json_decode((string) file_get_contents($path), true);
        return is_array($data) && isset($data['rules']) && is_array($data['rules'])
            ? $data['rules'] : [];
    }

    /** Recursively collect string leaves of a request array as [path, value]. */
    public static function leaves($arr, string $prefix, array &$out): void
    {
        foreach ((array) $arr as $key => $val) {
            $path = $prefix === '' ? (string) $key : "$prefix.$key";
            if (is_array($val)) {
                self::leaves($val, $path, $out);
            } elseif (is_string($val)) {
                $out[] = [$path, $val];
            }
        }
    }

    /** Write a sanitized value back to a dotted leaf path of a plain array. */
    public static function setLeaf(array &$bag, string $path, string $value): void
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
}
