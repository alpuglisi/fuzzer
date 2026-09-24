<?php

namespace App\Http\Controllers\Site;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/**
 * Hand-authored presentation layer: homepage, shared nav, and GET form pages
 * for the site's POST-only browser endpoints. Purely additive -- it never
 * reads or calls any generated cell controller, so it carries no injection
 * logic and no ground-truth label of its own.
 */
class SiteController extends Controller
{
    public function home()
    {
        return view('site.home');
    }

    public function loginForm()
    {
        return view('site.login');
    }

    public function registerForm()
    {
        return view('site.register');
    }

    public function contactForm()
    {
        return view('site.contact');
    }

    public function newsletterForm()
    {
        return view('site.newsletter');
    }

    public function editProfileForm(Request $request, string $action, string $profileUrl)
    {
        return view('site.edit_profile', [
            'action' => $action,
            'profile_url' => $profileUrl,
            'user' => $request->query('user', '1'),
        ]);
    }

    public function catalog()
    {
        $links = [];
        foreach (Route::getRoutes() as $route) {
            if (!in_array('GET', $route->methods(), true)) {
                continue;
            }
            $uri = '/' . ltrim($route->uri(), '/');
            if (in_array($uri, ['/', '/up', '/catalog'], true)) {
                continue;
            }
            $links[] = $uri;
        }
        sort($links);

        return view('site.catalog', ['links' => $links]);
    }
}
