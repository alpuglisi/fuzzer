@extends('layouts.site')
@section('title', 'Newsletter')
@section('content')
    <h2>Newsletter signup</h2>
    <form method="POST" action="/newsletter.php">
        <label for="email">Email</label>
        <input type="text" id="email" name="email">
        <button type="submit">Subscribe</button>
    </form>
@endsection
