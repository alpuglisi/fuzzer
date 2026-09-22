<?php
// Excerpt of Firefly III, app/Http/Middleware/Authenticate.php
// (AGPL-3.0-or-later). Source: repo firefly-iii/firefly-iii, commit
// 24dba21e4c44ebd6e41929ad4f53cd8c92ce6152.
// License note: AGPL-3.0 (copyleft) -- kept to the single illustrative
// method per this corpus's copyleft-handling rule.

/**
 * @throws AuthenticationException
 */
private function validateBlockedUser(?User $user, array $guards): void
{
    if (!$user instanceof User) {
        Log::warning('User is null, throw exception?');
    }
    if ($user instanceof User && 1 === (int) $user->blocked) {
        $message = (string) trans('firefly.block_account_logout');
        if ('email_changed' === $user->blocked_code) {
            $message = (string) trans('firefly.email_changed_logout');
        }
        Log::warning('User is blocked, cannot use authentication method.');
        app('session')->flash('logoutMessage', $message);
        $this->auth->logout();

        throw new AuthenticationException('Blocked account.', $guards);
    }
    Log::debug(sprintf('User #%d is not blocked.', $user->id));
}
