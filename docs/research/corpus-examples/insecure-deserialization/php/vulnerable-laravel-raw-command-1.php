<?php
// Excerpt of Laravel, src/Illuminate/Queue/CallQueuedHandler.php (MIT).
// Source: repo laravel/framework, commit
// a9cf9996942ff525e63f5c6b789466f4749bb996 -- the SAME real method as
// idiomatic-laravel-encrypted-command-1.php, its other branch (kept for
// backward compatibility with unencrypted queue payloads).

protected function getCommand(array $data)
{
    if (str_starts_with($data['command'], 'O:')) {
        // unserialize() runs directly on $data['command'] with no
        // cryptographic authentication of any kind -- if the queue
        // driver's storage (Redis, a DB table, SQS) is reachable or
        // tamperable by an attacker (a separate access-control issue on
        // the driver itself), this branch is a live PHP object-injection
        // gadget-chain RCE vector.
        return unserialize($data['command']);
    }
}
