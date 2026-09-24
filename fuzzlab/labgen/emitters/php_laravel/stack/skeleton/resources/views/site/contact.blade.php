@extends('layouts.site')
@section('title', 'Contact us')
@section('content')
    <h2>Contact us</h2>
    <form method="POST" action="/contact.php">
        <label for="message">Message</label>
        <textarea id="message" name="message" rows="5"></textarea>
        <button type="submit">Send</button>
    </form>
@endsection
