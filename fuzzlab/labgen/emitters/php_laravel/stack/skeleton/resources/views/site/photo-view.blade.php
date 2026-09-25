{{-- Hand-authored (CC-LAB-0239, docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md step 3),
     not generated: rendered via the "html_row_view" tail
     (fuzzlab.labgen.emitters.php_laravel's single_statement.php.j2 complexity)
     for LABGEN-CF-0001 (vulnerable) and LABGEN-CF-0002 (secure), which both
     `return view('site.photo-view', $rows)` with the same $rows shape
     (id, owner_id, caption, image_path, is_private). Byte-identical for both
     twins -- only the data differs -- so this file itself carries no
     leakage/fingerprint signal (R5). Raw echo of $caption is deliberate: the
     cell's own sink_context is a plain HTML-body value, same as every other
     converted page in this step. --}}
@extends('layouts.site')
@section('title', 'Photo')
@section('content')
    <h2>Photo #{{ $id }}</h2>
    <p><strong>Owner:</strong> {{ $owner_id }}</p>
    <p>{{ $caption }}</p>
    <p><em>{{ $image_path }}</em></p>
    <p>{{ $is_private ? 'Private' : 'Public' }}</p>
@endsection
