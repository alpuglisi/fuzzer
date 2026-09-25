{{-- GET /login.php (SiteController::loginForm, no data) and, since
     CC-LAB-0240, the POST failure path of LABGEN-PLA-0001/0002's
     `session_login` tail (`$error` set, status 401). The inline error copy
     and markup follow the real, pre-cutover page
     (`git show 876d2f9^:puppy-fort-factory/login.php`). Identical for both
     login twins (R5). --}}
@extends('layouts.site')
@section('title', 'Log in')
@section('content')
    <h2>Log in</h2>
    @isset($error)
        <p class="notice err">{{ $error }}</p>
    @endisset
    <form method="POST" action="/login.php">
        <label for="username">Username</label>
        <input type="text" id="username" name="username">
        <label for="password">Password</label>
        <input type="password" id="password" name="password">
        <button type="submit">Log in</button>
    </form>
    <p>New here? <a href="/register.php">Create an account</a>.</p>
@endsection
