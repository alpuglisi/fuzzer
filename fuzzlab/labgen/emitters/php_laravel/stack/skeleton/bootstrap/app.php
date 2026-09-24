<?php

use App\Http\Middleware\FzlCoverage;
use App\Http\Middleware\FzlWaf;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // The migrated real lab pages this stack reproduces have no
        // CSRF-token framework of their own (they are plain PHP forms), so
        // Laravel's default session-CSRF middleware would add an unmodeled,
        // unlabeled security control on top of every migrated POST page
        // that no `lab/ground-truth/` case accounts for and no Cell IR axis
        // represents -- exactly the "contaminating a cell's single labeled
        // vulnerability class with an unlabeled one" concern
        // `StackEnv.env_file_content()` already documents for APP_DEBUG.
        // Disabled globally rather than per-route so a future migrated POST
        // page cannot silently reintroduce it by omission.
        $middleware->validateCsrfTokens(except: ['*']);

        // CircleFeed's account-settings preference cookie (`CC-LAB-0220`,
        // insecure_deserialization/CWE-502) must reach the controller as the
        // exact bytes the client sent -- Laravel's default `EncryptCookies`
        // middleware would otherwise try to decrypt/MAC-verify it like any
        // other cookie and, failing that (an attacker-controlled cookie was
        // never encrypted by this app), silently hand the controller `null`
        // instead of the raw payload, masking the real vulnerability this
        // cell exists to demonstrate. Excluded by name only -- every other
        // cookie (the session cookie included) is still encrypted normally.
        $middleware->encryptCookies(except: ['pref']);

        // Global chain, order matters (`L-P3.3c-CUT`, re-homing the
        // hand-built app's `includes/prepend.php` chain onto Laravel
        // middleware): the WAF runs first (it may block and exit a hostile
        // request before it reaches app code); the coverage/db-fault shim
        // runs second so it instruments requests the WAF let through. Both
        // self-gate (PFF_WAF default off; X-Fzl-Cov absent by default), so
        // the default app and every ground-truth label are unchanged.
        $middleware->append([FzlWaf::class, FzlCoverage::class]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        // Grey-box db_fault capture (BUG-0049). Laravel's Illuminate\Routing\
        // Pipeline catches a controller QueryException at the router-dispatch
        // boundary and renders it to a 500 Response before it can propagate back
        // to the FzlCoverage middleware's own catch — so that middleware can
        // never observe it directly. The handler DOES invoke report() for the
        // exception, so record it here into the request-scoped static the
        // middleware reads after $next(). Returns void (does not return false),
        // so Laravel's default logging of the exception is unchanged. Self-gated
        // downstream: the middleware only reads this when X-Fzl-Cov is present,
        // so the default app and every ground-truth label are unaffected.
        $exceptions->report(function (\Illuminate\Database\QueryException $e): void {
            \App\Http\Middleware\FzlCoverage::$dbError = substr($e->getMessage(), 0, 300);
        });
    })->create();
