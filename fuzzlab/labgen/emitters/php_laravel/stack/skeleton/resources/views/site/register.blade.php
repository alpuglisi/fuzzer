{{-- GET /register.php (SiteController::registerForm, no data) and, since
     CC-LAB-0240, the POST result of LABGEN-PLA-0003's `register_insert`
     tail: `$error` + prefilled `$username`/`$email`/`$full_name` on a
     duplicate username (status 409), or `$registered_username` on success
     (status 200). Copy follows the real, pre-cutover page
     (`git show 876d2f9^:puppy-fort-factory/register.php`); every echo is
     Blade-escaped, as the real page escaped with e(). --}}
@extends('layouts.site')
@section('title', 'Register')
@section('content')
    <h2>Create an account</h2>
    @isset($registered_username)
        <p class="notice ok">Welcome to the pack, {{ $registered_username }}! You can now <a href="/login.php">log in</a>.</p>
    @else
        @isset($error)
            <p class="notice err">{{ $error }}</p>
        @endisset
        <form method="POST" action="/register.php">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" value="{{ $username ?? '' }}">
            <label for="full_name">Full name</label>
            <input type="text" id="full_name" name="full_name" value="{{ $full_name ?? '' }}">
            <label for="email">Email</label>
            <input type="text" id="email" name="email" value="{{ $email ?? '' }}">
            <label for="password">Password</label>
            <input type="password" id="password" name="password">
            <button type="submit">Register</button>
        </form>
        <p>Already have an account? <a href="/login.php">Log in</a>.</p>
    @endisset
@endsection
