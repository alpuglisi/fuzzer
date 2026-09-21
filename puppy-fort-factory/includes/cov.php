<?php
/*
 * Grey-box instrumentation shim (LAB-ONLY, Phase 3 T3.1/T3.4).
 *
 * NO-OP unless the tool sets the per-request correlation header `X-Fzl-Cov`, so the
 * default app and every ground-truth label are unchanged. When the header is present
 * it writes ONE JSON side-channel file per request, named by the sanitized id:
 *
 *   /tmp/fzl-cov/<id>  ->  {"files": {"/var/www/html/x.php": [lines]},
 *                          "db_fault": bool, "db_error": "..."}
 *
 * - Coverage comes from pcov (filtered to the app document root).
 * - db_fault is captured per request from PHP's error state: PHP 8's default
 *   mysqli_report throws mysqli_sql_exception on a SQL error, which surfaces as a
 *   fatal in error_get_last(); a set_error_handler also catches suppressed
 *   mysqli/SQL warnings. This attributes the fault to exactly one request with no
 *   racy DB-log tailing.
 *
 * The fuzzlab side reads these files via greybox.coverage.FileCoverageSource and
 * greybox.dbfault.FileDbFaultSource. Loopback-only lab instrumentation.
 */

$__fzl_cid = $_SERVER['HTTP_X_FZL_COV'] ?? '';
if ($__fzl_cid !== '') {
    $__fzl_cid = preg_replace('/[^A-Za-z0-9_.-]/', '', $__fzl_cid);
    $__fzl_dir = getenv('FZL_COV_DIR') ?: '/tmp/fzl-cov';
    @mkdir($__fzl_dir, 0777, true);

    if (extension_loaded('pcov')) {
        \pcov\start();
    }

    // Per-request DB-fault capture. Seed globals and catch suppressed warnings that
    // mention mysqli/SQL; the fatal path (uncaught mysqli_sql_exception) is read from
    // error_get_last() in the shutdown handler below.
    $GLOBALS['__fzl_db_fault'] = false;
    $GLOBALS['__fzl_db_error'] = '';
    set_error_handler(function ($no, $str) {
        if (stripos($str, 'mysqli') !== false || stripos($str, 'SQL') !== false) {
            $GLOBALS['__fzl_db_fault'] = true;
            if ($GLOBALS['__fzl_db_error'] === '') {
                $GLOBALS['__fzl_db_error'] = substr($str, 0, 300);
            }
        }
        return false;   // let PHP's normal handler run too
    });

    register_shutdown_function(function () use ($__fzl_cid, $__fzl_dir) {
        $out = ['files' => new stdClass(), 'db_fault' => false, 'db_error' => ''];

        if (extension_loaded('pcov')) {
            \pcov\stop();
            // Collect everything pcov recorded (pcov.directory already scopes it to the
            // app), then keep only app files by PATH PREFIX. Do NOT pass a directory as
            // pcov's inclusive filter — that filter is a list of FILE paths, so a
            // directory matches nothing and collect() returns empty.
            $cov = \pcov\collect();
            $files = [];
            foreach ($cov as $file => $lines) {
                if (strpos($file, '/var/www/html/') === 0) {
                    $files[$file] = array_keys($lines);
                }
            }
            if ($files) {
                $out['files'] = $files;
            }
        }

        // A fatal (e.g. an uncaught mysqli_sql_exception from an error-based SQLi) shows here.
        $last = error_get_last();
        if ($last && (stripos($last['message'], 'mysqli') !== false
                      || stripos($last['message'], 'SQL') !== false)) {
            $GLOBALS['__fzl_db_fault'] = true;
            if (($GLOBALS['__fzl_db_error'] ?? '') === '') {
                $GLOBALS['__fzl_db_error'] = substr($last['message'], 0, 300);
            }
        }
        $out['db_fault'] = (bool)($GLOBALS['__fzl_db_fault'] ?? false);
        $out['db_error'] = (string)($GLOBALS['__fzl_db_error'] ?? '');

        @file_put_contents($__fzl_dir . '/' . $__fzl_cid, json_encode($out));
    });
}
