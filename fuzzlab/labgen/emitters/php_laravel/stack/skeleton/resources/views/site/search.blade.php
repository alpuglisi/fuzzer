{{-- Hand-authored (CC-LAB-0240, docs/LAB_PFF_JSON_TO_HTML_PLAN.md), not
     generated: rendered via the "html_list_view" tail
     (fuzzlab.labgen.emitters.php_laravel's single_statement.php.j2 complexity)
     for LABGEN-PL-RP-0001 (vulnerable) and LABGEN-PL-RP-0002 (secure) -- the
     /search.php SQLi twins -- which both
     `return view('site.search', ['rows' => $rows])` with the same $rows
     shape (a LIST of `products` rows from the LIKE query). Byte-identical for
     both twins -- only the data differs (R5).

     Deliberately does NOT echo the `q` value back: this page's two XSS
     reflections are separate cells (LABGEN-PL-RP-0003..0006, `render_only`
     complexity, their own generated views), exempted at this URL
     (PFF-0003, lab/ground-truth/migration-exemptions.yaml) -- the SQLi
     twins' shared view must not re-introduce a reflection of its own. R1:
     one result card is deliberately at least 300 bytes longer than the
     no-results state -- guarded by a direct byte-length test. --}}
@extends('layouts.site')
@section('title', 'Search')
@section('content')
    <h1>Search the fort catalogue</h1>
    <form method="get" action="/search.php">
        <input type="text" name="q" placeholder="Try 'chew' or 'treat'">
        <button class="btn" type="submit">Search</button>
    </form>
    <div class="grid">
        @forelse ($rows as $row)
            @include('site.partials.product-card')
        @empty
            <p>No forts matched your search.</p>
        @endforelse
    </div>
@endsection
