<?php
// Excerpt of Laravel, src/Illuminate/Queue/CallQueuedHandler.php (MIT).
// Source: repo laravel/framework, commit
// a9cf9996942ff525e63f5c6b789466f4749bb996. This is the same real method
// as vulnerable-laravel-raw-command-1.php in this directory -- the two
// branches of getCommand() -- kept as separate files since they are the
// idiomatic/vulnerable contrast this pair documents.

protected function getCommand(array $data)
{
    if ($this->container->bound(Encrypter::class)) {
        // unserialize() only ever runs on plaintext that has already
        // passed the Encrypter's own AEAD authentication -- a forged or
        // tampered payload fails decryption before unserialize() is
        // reached at all.
        return unserialize($this->container[Encrypter::class]->decrypt($data['command']));
    }

    throw new RuntimeException('Unable to extract job payload.');
}
