{{-- Hand-authored (CC-LAB-0239, docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md step 3),
     not generated: rendered via the "html_row_view" tail
     (fuzzlab.labgen.emitters.php_laravel's single_statement.php.j2 complexity)
     for LABGEN-BC-0005 (vulnerable) and LABGEN-BC-0006 (secure), which both
     `return view('site.booking-checkout', $rows)` with the same $rows shape
     (booked, charged_amount). Byte-identical for both twins -- only the data
     differs -- so this file itself carries no leakage/fingerprint signal
     (R5). `data-charged-amount` is PriceIntegrityBypassStrategy's own
     detection anchor (CC-FUZZ-0047, R1) -- an exact-matched HTML attribute,
     replacing the old `"charged_amount":"..."` JSON-fragment match. Its
     value must render as the literal string Eloquent/Blade received, with
     no numeric reformatting (e.g. trailing-zero collapse), or the strategy's
     exact match on the canary would fail. --}}
@extends('layouts.site')
@section('title', 'Booking confirmed')
@section('content')
    <h2>Booking confirmed</h2>
    <p data-charged-amount="{{ $charged_amount }}">Charged: ${{ $charged_amount }}</p>
@endsection
