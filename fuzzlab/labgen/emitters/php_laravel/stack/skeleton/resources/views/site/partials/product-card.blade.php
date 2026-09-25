{{-- Hand-authored (CC-LAB-0240): one product card, shared by site.products
     (/products.php) and site.search (/search.php) -- the real, pre-cutover
     pages' own `.card` markup (`git show 876d2f9^:puppy-fort-factory/
     {products,search}.php`), plus the product page's own add-to-cart form.
     Expects `$row`, one `products` row; reads only columns present in both
     live-boot harnesses' schema (R6). R1: one card must stay at least 300
     bytes longer than site.search's no-results state -- guarded by a direct
     byte-length test in both live-boot suites. --}}
<div class="card" data-product-id="{{ $row->id }}">
    <h3><a href="/product.php?id={{ (int) $row->id }}">{{ $row->name }}</a></h3>
    <p class="price">${{ number_format((float) $row->price, 2) }}</p>
    <p class="muted">Category: {{ $row->category }} &middot; In stock: {{ (int) $row->stock }}</p>
    <p>{{ $row->description }}</p>
    <p><a class="btn" href="/product.php?id={{ (int) $row->id }}">View this fort</a></p>
    <form action="/add_to_cart.php" method="post">
        <input type="hidden" name="product_id" value="{{ (int) $row->id }}">
        <input type="hidden" name="quantity" value="1">
        <button class="btn" type="submit">Add to cart</button>
    </form>
</div>
