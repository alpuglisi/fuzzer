<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Grey-box instrumentation middleware (LAB-ONLY, `L-P3.3c-CUT`: the Laravel scaffold
 * successor to the hand-built app's `includes/cov.php`, re-homed here because the
 * fixture directory it lived in is retired).
 *
 * NO-OP unless the request carries the per-request correlation header `X-Fzl-Cov`, so
 * the default app and every ground-truth label are unchanged. When the header is
 * present it writes ONE JSON side-channel file per request, named by the sanitized
 * id — the same contract `scripts/greybox_e2e.sh` and
 * `fuzzlab.greybox.coverage.FileCoverageSource` / `fuzzlab.greybox.dbfault.
 * FileDbFaultSource` already read from the PHP predecessor's shim, unchanged:
 *
 *   FZL_COV_DIR/<id>  ->  {"files": {"<path>": [lines]}, "db_fault": bool,
 *                          "db_error": "..."}
 *
 * - Coverage comes from pcov (filtered to the app document root), when loaded.
 * - `db_fault` is captured from an uncaught `Illuminate\Database\QueryException`
 *   propagating out of the request (Laravel's wrapped equivalent of a raw
 *   `mysqli_sql_exception`) — the migrated controllers go through `DB::table()`/
 *   `DB::select()` (the query builder), so a malformed identifier-position SQL
 *   injection surfaces here exactly as it did as a PHP fatal in the predecessor.
 *   The exception is re-thrown after recording so Laravel's own exception handler
 *   still renders its usual response — this middleware only observes, never
 *   swallows.
 */
class FzlCoverage
{
    public function handle(Request $request, Closure $next): Response
    {
        $cid = (string) $request->header('X-Fzl-Cov', '');
        if ($cid === '') {
            return $next($request);
        }
        $cid = preg_replace('/[^A-Za-z0-9_.-]/', '', $cid);
        $dir = getenv('FZL_COV_DIR') ?: '/tmp/fzl-cov';
        @mkdir($dir, 0777, true);

        $pcovLoaded = extension_loaded('pcov');
        if ($pcovLoaded) {
            \pcov\start();
        }

        $dbFault = false;
        $dbError = '';
        $response = null;
        $caught = null;

        try {
            $response = $next($request);
        } catch (QueryException $e) {
            $dbFault = true;
            $dbError = substr($e->getMessage(), 0, 300);
            $caught = $e;
        } catch (Throwable $e) {
            // Not a DB fault, but this middleware must not swallow an unrelated
            // exception — record coverage below, then re-throw unchanged.
            $caught = $e;
        }

        $out = ['files' => new \stdClass(), 'db_fault' => $dbFault, 'db_error' => $dbError];
        if ($pcovLoaded) {
            \pcov\stop();
            $cov = \pcov\collect();
            $files = [];
            foreach ($cov as $file => $lines) {
                if (strpos($file, base_path()) === 0) {
                    $files[$file] = array_keys($lines);
                }
            }
            if ($files) {
                $out['files'] = $files;
            }
        }
        @file_put_contents($dir . '/' . $cid, json_encode($out));

        if ($caught !== null) {
            throw $caught;
        }
        return $response;
    }
}
