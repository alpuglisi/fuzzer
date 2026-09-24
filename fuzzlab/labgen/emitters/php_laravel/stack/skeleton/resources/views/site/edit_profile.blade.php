@extends('layouts.site')
@section('title', 'Edit profile')
@section('content')
    <h2>Edit profile</h2>
    <form method="POST" action="{{ $action }}">
        <input type="hidden" name="user" value="{{ $user }}">
        <label for="bio">Bio</label>
        <textarea id="bio" name="bio" rows="5"></textarea>
        <button type="submit">Save</button>
    </form>
    <p><a href="{{ $profile_url }}">Back to profile</a></p>
@endsection
