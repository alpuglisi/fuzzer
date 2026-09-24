@extends('layouts.site')
@section('title', 'Log in')
@section('content')
    <h2>Log in</h2>
    <form method="POST" action="/login.php">
        <label for="username">Username</label>
        <input type="text" id="username" name="username">
        <label for="password">Password</label>
        <input type="password" id="password" name="password">
        <button type="submit">Log in</button>
    </form>
    <p>New here? <a href="/register.php">Create an account</a>.</p>
@endsection
