<?php
/*
 * Global auto_prepend chain (LAB-ONLY).
 *
 * PHP's `auto_prepend_file` holds a SINGLE path, so the WAF prefilter and the
 * grey-box coverage shim cannot each be wired with their own auto_prepend line (the
 * last one set would silently win). This file chains both. Both self-gate — the WAF
 * is off unless PFF_WAF=on, and the coverage shim is a no-op unless the request
 * carries X-Fzl-Cov — so the default app and every ground-truth label are unchanged.
 *
 * Order matters: the WAF runs first (it may block and exit a hostile request before
 * it reaches app code); the coverage shim runs second so it instruments requests the
 * WAF let through.
 */
$__pff_inc = __DIR__;
if (is_file($__pff_inc . '/waf.php')) {
    require_once $__pff_inc . '/waf.php';
}
if (is_file($__pff_inc . '/cov.php')) {
    require_once $__pff_inc . '/cov.php';
}
