@extends('layouts.site')
@section('title', 'Catalog')
@section('content')
    <h2>Catalog</h2>
    <p>Every generated page on this site, for direct navigation.</p>
    <ul class="site-list">
        @foreach ($links as $link)
            <li><a href="{{ $link }}">{{ $link }}</a></li>
        @endforeach
    </ul>
@endsection
