@extends('layouts.site')
@section('title', 'Register')
@section('content')
    <h2>Create an account</h2>
    <form method="POST" action="/register.php">
        <label for="username">Username</label>
        <input type="text" id="username" name="username">
        <label for="full_name">Full name</label>
        <input type="text" id="full_name" name="full_name">
        <label for="email">Email</label>
        <input type="text" id="email" name="email">
        <label for="password">Password</label>
        <input type="password" id="password" name="password">
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="/login.php">Log in</a>.</p>
@endsection
