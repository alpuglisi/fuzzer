{{-- Hand-authored (CC-LAB-0240, docs/LAB_PFF_JSON_TO_HTML_PLAN.md), not
     generated: rendered via the "html_list_view" tail
     (fuzzlab.labgen.emitters.php_laravel's single_statement.php.j2 complexity)
     for LABGEN-RPL-PRODUCT (vulnerable) and LABGEN-RPL-PRODUCT-BOUND
     (secure), which both `return view('site.product', ['rows' => $rows])`
     with the same $rows shape (a LIST of `products` rows, from
     `DB::select("SELECT * FROM products ...")`). Byte-identical for both
     twins -- only the data differs -- so this file itself carries no
     leakage/fingerprint signal (R5).

     Copy and structure follow the real, pre-cutover page
     (`git show 876d2f9^:puppy-fort-factory/product.php`), including its own
     empty-state text. R1: the found state (the product article plus its
     add-to-cart form) is deliberately at least 300 bytes longer than the
     not-found state, so SqliBooleanStrategy's length-similarity check keeps
     a clear found/not-found signal once wrapped in the shared layout --
     guarded by a direct byte-length test, not by this comment. Only columns
     present in BOTH live-boot harnesses' `products` schema are read (R6). --}}
@extends('layouts.site')
@section('title', 'Product')
@section('content')
    @forelse ($rows as $row)
        <article class="product-detail" data-product-id="{{ $row->id }}">
            <p><a href="/products.php">&larr; Back to shop</a></p>
            <h1>{{ $row->name }}</h1>
            <p class="price">${{ number_format((float) $row->price, 2) }}</p>
            <p class="muted">Category: {{ $row->category }} &middot; In stock: {{ (int) $row->stock }}</p>
            <p>{{ $row->description }}</p>

            <form action="/add_to_cart.php" method="post">
                <input type="hidden" name="product_id" value="{{ (int) $row->id }}">
                <label>Quantity
                    <input type="number" name="quantity" value="1" min="1" style="width:70px">
                </label>
                <button class="btn" type="submit">Add to cart</button>
            </form>
        </article>
    @empty
        <p>Sorry, we couldn't find that fort.</p>
        <p><a href="/products.php">Back to the shop</a></p>
    @endforelse
@endsection
