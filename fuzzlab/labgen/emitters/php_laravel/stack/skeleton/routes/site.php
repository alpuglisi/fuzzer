<?php
// Hand-authored, part of the stack skeleton (not generated per cell): the
// homepage, shared nav, and GET form pages that make the site navigable in
// a browser. Never touched by the route accumulator -- see
// docs/LAB_BROWSABLE_APPS_PLAN.md step 1. Registered from routes/web.php's
// fixed header, before the per-cell fragments.

use App\Http\Controllers\Site\SiteController;
use Illuminate\Support\Facades\Route;

Route::get('/', [SiteController::class, 'home']);
Route::get('/catalog', [SiteController::class, 'catalog']);

Route::get('/login.php', [SiteController::class, 'loginForm']);
Route::get('/register.php', [SiteController::class, 'registerForm']);
Route::get('/contact.php', [SiteController::class, 'contactForm']);
Route::get('/newsletter.php', [SiteController::class, 'newsletterForm']);

Route::get('/edit_profile.php', fn () => app(SiteController::class)->editProfileForm(
    request(),
    '/edit_profile.php',
    '/profile.labgen-plrp-0402.php',
));
Route::get('/edit_profile.labgen-plrp-0401.php', fn () => app(SiteController::class)->editProfileForm(
    request(),
    '/edit_profile.labgen-plrp-0401.php',
    '/profile.php',
));
