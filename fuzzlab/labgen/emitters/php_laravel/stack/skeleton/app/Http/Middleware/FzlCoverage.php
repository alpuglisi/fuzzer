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
 * - `db_fault` is captured from an `Illuminate\Database\QueryException` raised
 *   while handling the request (Laravel's wrapped equivalent of a raw
 *   `mysqli_sql_exception`) — the migrated controllers go through `DB::table()`/
 *   `DB::select()` (the query builder) and `whereRaw()`, so a malformed
 *   identifier/literal-position SQL injection surfaces as one of these.
 *
 *   IMPORTANT (BUG-0049): the exception does NOT propagate out of `$next()` back
 *   to this middleware. Laravel's `Illuminate\Routing\Pipeline` catches a
 *   controller exception at the innermost router-dispatch boundary and renders
 *   it to a 500 `Response` *before* it unwinds back through the global
 *   middleware, so the `catch (QueryException)` below can never see it. The DB
 *   fault is therefore captured by the `report()` hook registered in
 *   `bootstrap/app.php`, which Laravel's handler DOES invoke for the exception;
 *   that hook writes the message into the request-scoped static `self::$dbError`,
 *   which this middleware reads after `$next()`. The `try/catch` is kept only as
 *   belt-and-suspenders for an exception that genuinely does propagate here.
 */
class FzlCoverage
{
    /**
     * Request-scoped capture of the last DB-layer error message, set by the
     * `QueryException` `report()` hook in `bootstrap/app.php` (see the class
     * doc). Reset at the start of each instrumented request. Statics do not
     * persist across requests under mod_php/PHP-FPM, and the reset guards the
     * edge case regardless.
     */
    public static ?string $dbError = null;

    public function handle(Request $request, Closure $next): Response
    {
        $cid = (string) $request->header('X-Fzl-Cov', '');
        if ($cid === '') {
            return $next($request);
        }
        $cid = preg_replace('/[^A-Za-z0-9_.-]/', '', $cid);
        $dir = getenv('FZL_COV_DIR') ?: '/tmp/fzl-cov';
        @mkdir($dir, 0777, true);

        // Reset the per-request DB-fault capture before dispatch; the report()
        // hook (bootstrap/app.php) fills it in synchronously during $next().
        self::$dbError = null;

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

        // Primary path: the QueryException was caught+rendered inside Laravel's
        // routing pipeline (never reaching the catch above) but recorded by the
        // report() hook into self::$dbError. Honour it.
        if (self::$dbError !== null) {
            $dbFault = true;
            $dbError = substr(self::$dbError, 0, 300);
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
