{{-- Hand-authored (CC-LAB-0240, docs/LAB_PFF_JSON_TO_HTML_PLAN.md), not
     generated: rendered via the "html_list_view" tail
     (fuzzlab.labgen.emitters.php_laravel's single_statement.php.j2 complexity)
     for LABGEN-PLRP-G2-0001 (secure-only), which does
     `return view('site.products', ['rows' => $rows])` with a LIST of
     category-filtered `products` rows. Copy follows the real, pre-cutover
     page (`git show 876d2f9^:puppy-fort-factory/products.php`). --}}
@extends('layouts.site')
@section('title', 'Shop')
@section('content')
    <h1>Shop all forts</h1>
    <div class="grid">
        @forelse ($rows as $row)
            @include('site.partials.product-card')
        @empty
            <p>No forts in that category yet. <a href="/products.php">Browse every fort</a>.</p>
        @endforelse
    </div>
@endsection
