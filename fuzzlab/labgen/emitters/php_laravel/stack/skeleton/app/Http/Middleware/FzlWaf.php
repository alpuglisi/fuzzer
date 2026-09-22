<?php

namespace App\Http\Middleware;

use App\Support\WafFilter;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Lab WAF middleware — a configurable request pre-filter for the generated PHP lab
 * (`L-P3.3c-CUT`: the Laravel scaffold successor to the hand-built app's
 * `includes/waf.php`, re-homed here because the fixture directory it lived in is
 * retired).
 *
 * DELIBERATELY NAIVE and signature-based, same as its predecessor: it exists to give
 * the toolkit's Phase 8 mutation engine a real, controllable target to learn to
 * bypass (filter-transformation learning, FR-MUT-3) — it is NOT a real WAF and
 * provides no real protection.
 *
 * DEFAULT OFF (D16). With `PFF_WAF` unset/off this middleware is a no-op, so the
 * lab behaves exactly as if it were absent and every existing ground-truth label
 * stays valid. Registered globally in `bootstrap/app.php` so it runs before every
 * request without editing any route — and does nothing until enabled.
 *
 * Configuration (environment variables, read per request — no rebuild to toggle):
 *   PFF_WAF        on|off              (default off)
 *   PFF_WAF_MODE   block|sanitize|log  (default block)
 *   PFF_WAF_RULES  path to the ruleset JSON (default storage/app/waf-rules.json --
 *                  `fuzzlab.labgen.assemble` copies the shared, single-source
 *                  `lab/waf-rules.json` there at build time, so this middleware
 *                  never needs a sibling `lab/` checkout at runtime)
 *
 * Modes mirror the PHP predecessor exactly:
 *   block     — a matching request gets 403 and stops (evasion target: avoid the rule)
 *   sanitize  — the matched fragment is stripped from the input the app sees
 *               (evasion target: learn what the filter removes and adapt)
 *   log       — matches are logged only; the request proceeds unchanged (observe)
 */
class FzlWaf
{
    public function handle(Request $request, Closure $next): Response
    {
        $on = strtolower((string) (getenv('PFF_WAF') ?: 'off'));
        if (!in_array($on, ['1', 'on', 'true', 'yes'], true)) {
            return $next($request);                        // default OFF — no-op
        }

        $mode = strtolower((string) (getenv('PFF_WAF_MODE') ?: 'block'));
        $rulesPath = getenv('PFF_WAF_RULES') ?: storage_path('app/waf-rules.json');
        $rules = WafFilter::loadRules($rulesPath);
        if (!$rules) {
            return $next($request);
        }

        foreach (['query', 'request', 'cookies'] as $bag) {
            $leaves = [];
            WafFilter::leaves($request->{$bag}->all(), '', $leaves);
            foreach ($leaves as [$path, $value]) {
                $res = WafFilter::checkValue($value, $rules);
                if (!$res['hits']) {
                    continue;
                }
                $effective = $mode;
                foreach ($res['hits'] as $hit) {
                    if (!empty($hit['action'])) {
                        $effective = $hit['action'];
                    }
                }
                error_log(sprintf(
                    '[fzl-waf] %s param %s matched %s (mode=%s)',
                    $bag, $path, implode(',', array_column($res['hits'], 'id')), $effective
                ));
                if ($effective === 'log') {
                    continue;
                }
                if ($effective === 'sanitize') {
                    $this->setLeaf($request->{$bag}, $path, $res['clean']);
                    continue;
                }
                // (WafFilter::setLeaf is used directly by the standalone test
                // driver over a plain array; the Laravel input bag needs
                // this thin, Illuminate-aware wrapper below instead.)
                // block (default)
                return response(
                    '<!doctype html><title>Request blocked</title>'
                    . '<h1>403 — request blocked by the lab filter</h1>'
                    . '<p>Matched rule(s): '
                    . htmlspecialchars(implode(', ', array_column($res['hits'], 'id')))
                    . '</p>',
                    403,
                    ['Content-Type' => 'text/html; charset=utf-8']
                );
            }
        }

        return $next($request);
    }

    /** Write a sanitized value back to a dotted leaf path of a Laravel input bag. */
    private function setLeaf($bag, string $path, string $value): void
    {
        $keys = explode('.', $path);
        $data = $bag->all();
        $ref = &$data;
        foreach ($keys as $i => $key) {
            if ($i === count($keys) - 1) {
                $ref[$key] = $value;
            } elseif (isset($ref[$key]) && is_array($ref[$key])) {
                $ref = &$ref[$key];
            } else {
                return;
            }
        }
        $bag->replace($data);
    }
}
