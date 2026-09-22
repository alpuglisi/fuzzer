<?php
// Manufactured vulnerable variant, derived from
// idiomatic-firefly-blocked-check-1.php (Firefly III, AGPL-3.0-or-later).
// Illustrates a common real-world anti-pattern: the blocked-account check
// only runs at login (inside the login controller), not as middleware
// re-validated on every subsequent authenticated request -- so an account
// blocked by an admin mid-session stays fully authorized until its session
// cookie naturally expires (CWE-287: Improper Authentication /
// CWE-613: Insufficient Session Expiration).
// License note: derived from AGPL-3.0 code -- see the idiomatic entry's
// license note; the same caution applies here.

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $user = $this->attemptLogin($request);

        // Blocked-status check happens once, here, at login time only.
        // No equivalent check runs on the Authenticate middleware that
        // gates every later request in this session -- contrast with
        // idiomatic-firefly-blocked-check-1.php's validateBlockedUser(),
        // which the real app re-runs on every request via its middleware
        // handle() method.
        if (1 === (int) $user->blocked) {
            Auth::logout();
            return redirect('/login')->withErrors(['account' => trans('firefly.block_account_logout')]);
        }

        Auth::login($user);

        return redirect()->intended('/');
    }
}
